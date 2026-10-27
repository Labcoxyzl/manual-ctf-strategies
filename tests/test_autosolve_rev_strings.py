"""REV02 fixtures use independent compiled executables and bounded fake FLOSS JSON."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from collections import deque
from pathlib import Path
from unittest import mock

from scripts.autosolve_lib.profiles import rev_strings
from scripts.autosolve_lib import setup as autosolve_setup
from scripts.autosolve_lib import core


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autosolve.py'


@unittest.skipUnless(shutil.which('gcc'), 'GCC is unavailable')
class ReverseStringsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def build(self, name, body, *, compiler='gcc', optimization='-O0', strip=False):
        source = self.root / f'{name}.c'
        target = self.root / name
        source.write_text(body)
        command = [compiler, optimization, '-o', str(target), str(source)]
        if strip:
            command.insert(2, '-s')
        subprocess.run(command, check=True, capture_output=True)
        return target

    def test_stack_string_exact_bytes_and_instruction_offsets(self):
        phrase = b'STACK_HELLO'
        assignments = ''.join(f's[{index}]={byte};' for index, byte in enumerate(phrase + b'\0'))
        binary = self.build('stack', 'int probe(void){volatile char s[32];'
                            + assignments + 'return s[1];} int main(void){return probe();}')
        before = hashlib.sha256(binary.read_bytes()).digest()
        rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
        matches = [row for row in rows if row['kind'] == 'stack' and row['data'] == phrase]
        self.assertEqual(len(matches), 1, (rows, warnings))
        row = matches[0]
        self.assertEqual(row['state'], 'candidate')
        self.assertTrue(row['source_locator']['instruction_file_offsets'])
        payload = binary.read_bytes()
        for offset in row['source_locator']['instruction_file_offsets']:
            self.assertEqual(payload[offset], 0xc6)  # x86 mov byte ptr [bp+disp], imm8
        self.assertEqual(hashlib.sha256(binary.read_bytes()).digest(), before)

    def test_xor_string_from_object_symbol_and_heldout_layout(self):
        phrase = b'hello secret message in the data'
        key = 0x37
        encoded = bytes(byte ^ key for byte in phrase)
        initializer = ','.join(str(byte) for byte in encoded + b'\0')
        source = ('volatile unsigned char encoded[] = {' + initializer + '};'
                  'int main(void){for(int i=0;i<' + str(len(phrase))
                  + ';i++)encoded[i]^=0x37;return encoded[0];}')
        for name, optimization, strip in (('xor_gcc', '-O0', False),
                                          ('xor_heldout', '-O2', True)):
            binary = self.build(name, source, optimization=optimization, strip=strip)
            rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
            matches = [row for row in rows if row['kind'] == 'xor' and row['data'] == phrase]
            self.assertEqual(len(matches), 1, (name, rows, warnings))
            row = matches[0]
            self.assertEqual(row['state'], 'candidate')
            self.assertEqual(row['key_hex'], f'{key:02x}')
            offset = row['source_locator']['file_offset']
            self.assertEqual(binary.read_bytes()[offset:offset + len(phrase)], encoded)

    def test_xor_string_without_dictionary_words_uses_decoder_code(self):
        cases = [('gcc_o0', 'gcc', '-O0', False, b'copper harbor violet route', 0x37),
                 ('gcc_o2_stripped', 'gcc', '-O2', True, b'silver meadow branch crossing', 0x59)]
        if shutil.which('clang-16'):
            cases.append(('clang_o2', 'clang-16', '-O2', False,
                          b'orchard lantern melody river', 0x4b))
        for name, compiler, optimization, strip, phrase, key in cases:
            with self.subTest(name=name):
                encoded = bytes(byte ^ key for byte in phrase)
                source = ('volatile unsigned char payload[] = {' +
                          ','.join(str(byte) for byte in encoded + b'\0') + '};'
                          'int main(void){for(unsigned i=0;i<' + str(len(phrase)) +
                          ';i++)payload[i]^=' + str(key) + ';return payload[0];}')
                binary = self.build(name, source, compiler=compiler,
                                    optimization=optimization, strip=strip)
                rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
                matches = [row for row in rows if row['kind'] == 'xor' and row['data'] == phrase]
                self.assertEqual(len(matches), 1, (name, rows, warnings))
                row = matches[0]
                self.assertEqual(row['key_hex'], f'{key:02x}')
                self.assertEqual(row['state'], 'candidate')
                offset = row['source_locator']['file_offset']
                self.assertEqual(binary.read_bytes()[offset:offset + len(encoded)], encoded)

    def test_jump_past_zero_and_prologue_cannot_claim_xor_plaintext(self):
        phrase = b'river beacon mossy path'
        encoded = bytes(byte ^ 0x59 for byte in phrase)
        prefixes = {
            'call_before_main': ('dummy:\ncall decode\nret\nmain:\n'
                                 'mov $10, %eax\njmp body\nback:\njmp main\n'),
            'decoy_after_main': ('main:\nmov $22, %eax\njmp body\n'
                                 'decoy:\njmp decode\nprior:\nnop\njmp prior\n'),
            'window_evicts_bypass': ('main:\nmov $22, %eax\njmp body\n' +
                                     'nop\n' * 120 +
                                     'decoy:\njmp decode\nprior:\nnop\njmp prior\n'),
            'indirect_bypass_with_decoy': ('main:\nlea body(%rip), %r9\n'
                                           'jmp *%r9\ndecoy:\njmp decode\n'
                                           'prior:\nnop\njmp prior\n'),
        }
        for name, prefix in prefixes.items():
            with self.subTest(name=name):
                source = self.root / f'{name}.S'
                binary = self.root / name
                source.write_text('.section .data\npayload:\n.byte ' +
                                  ','.join(map(str, encoded + b'\0')) +
                                  '\n.section .text\n.globl main\n' + prefix +
                                  'decode:\nsub $8, %rsp\nxor %eax, %eax\n.p2align 4\n'
                                  'body:\nmov %eax, %ecx\nadd $1, %eax\n'
                                  'movzbl payload(%rcx), %edx\nxor $0x59, %edx\n'
                                  'mov %dl, payload(%rcx)\ncmp $23, %eax\n'
                                  'jne body\nadd $8, %rsp\nret\n'
                                  '.section .note.GNU-stack,"",@progbits\n')
                subprocess.run(['gcc', '-no-pie', '-o', str(binary), str(source)],
                               check=True, capture_output=True)
                rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
                self.assertFalse(any(row['data'] == phrase for row in rows),
                                 (rows, warnings))

    def test_unrelated_xor_constant_does_not_decode_random_data(self):
        binary = self.build('unrelated_xor',
                            'volatile unsigned char constants[] = {' +
                            ','.join(str(byte) for byte in bytes(range(16, 48))) +
                            '}; int main(void){unsigned x=0x1234; x^=0x59;'
                            'return x + constants[0];}', optimization='-O2', strip=True)
        rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
        self.assertEqual([row for row in rows if row['kind'] == 'xor'], [], warnings)

    def test_stale_register_address_does_not_claim_xor_plaintext(self):
        encoded = bytes(byte ^ 0x37 for byte in b'copper harbor violet route')
        data = ('.section .data\n.globl payload\n.type payload, @object\n'
                '.size payload, 26\npayload:\n.byte ' + ','.join(map(str, encoded)) +
                '\n.globl noise\nnoise:\n.byte 1\n.space 512\n.section .text\n')
        cases = {
            'alias_write': ('lea payload(%rip), %rax\nmov $noise, %eax\n'
                            'movb (%rax), %cl\nxorb $0x37, %cl\nmovb %cl, (%rax)\n'),
            'alias_write_after_xor': ('lea payload(%rip), %rax\nmovb (%rax), %cl\n'
                                      'xorb $0x37, %cl\nmov $noise, %eax\n'
                                      'movb %cl, (%rax)\n'),
            'result_overwrite': ('lea payload(%rip), %rax\nmovb (%rax), %cl\n'
                                 'xorb $0x37, %cl\nmovb $0, %cl\nmovb %cl, (%rax)\n'),
            'wrong_store_register': ('lea payload(%rip), %rax\nmovb (%rax), %cl\n'
                                     'xorb $0x37, %cl\nmovb $0, %dl\nmovb %dl, (%rax)\n'),
            'wrong_byte_lane': ('lea payload(%rip), %rax\nmovb (%rax), %cl\n'
                                'xorb $0x37, %cl\nmovb %cl, %dh\nmovb %dl, (%rax)\n'),
            'function_boundary': ('lea payload(%rip), %rax\nret\n'
                                  'other:\nmovb (%rax), %cl\nxorb $0x37, %cl\n'
                                  'movb %cl, (%rax)\n'),
            'unknown_direct_base': ('mov $noise, %eax\n' +
                                    ''.join(f'xorb $0x37, payload+{i}(%rax)\n'
                                            for i in range(len(encoded)))),
            'unknown_index_base': ('mov $26, %eax\nmovb payload(%rax), %cl\n'
                                   'xorb $0x37, %cl\nmovb %cl, payload(%rax)\n'),
            'one_byte_only': ('lea payload(%rip), %rax\nmovb (%rax), %cl\n'
                              'xorb $0x37, %cl\nmovb %cl, (%rax)\n'),
            'false_bound_flags': ('xor %esi, %esi\njmp compare\nbody:\n'
                                  'mov %esi, %edx\nadd $1, %esi\n'
                                  'lea payload(%rip), %rax\nmovb (%rax,%rdx), %cl\n'
                                  'xorb $0x37, %cl\nmovb %cl, (%rax,%rdx)\n'
                                  'compare:\ncmp $26, %esi\nxor %ebx, %ebx\njne body\n'),
            'skipped_decoder_body': ('xor %esi, %esi\njmp compare\nbody:\njmp compare\n'
                                     'mov %esi, %edx\nadd $1, %esi\n'
                                     'lea payload(%rip), %rax\nmovb (%rax,%rdx), %cl\n'
                                     'xorb $0x37, %cl\nmovb %cl, (%rax,%rdx)\n'
                                     'compare:\ncmp $26, %esi\njne body\n'),
            'counter_alias_reset': ('push %rbp\nmov %rsp, %rbp\nsub $16, %rsp\n'
                                    'lea -4(%rbp), %r8\nmovl $0, -4(%rbp)\njmp compare\n'
                                    'body:\nmov -4(%rbp), %edx\nlea payload(%rip), %rax\n'
                                    'movb (%rax,%rdx), %cl\nxorb $0x37, %cl\n'
                                    'movb %cl, (%rax,%rdx)\naddl $1, -4(%rbp)\n'
                                    'movl $0, (%r8)\ncompare:\ncmpl $25, -4(%rbp)\n'
                                    'jbe body\nleave\n'),
            'counter_alias_preloop_set': ('push %rbp\nmov %rsp, %rbp\nsub $16, %rsp\n'
                                          'lea -4(%rbp), %r8\nmovl $0, -4(%rbp)\n'
                                          'movl $25, (%r8)\njmp compare\n'
                                          'body:\nmov -4(%rbp), %edx\n'
                                          'lea payload(%rip), %rax\n'
                                          'movb (%rax,%rdx), %cl\nxorb $0x37, %cl\n'
                                          'movb %cl, (%rax,%rdx)\naddl $1, -4(%rbp)\n'
                                          'compare:\ncmpl $25, -4(%rbp)\njbe body\nleave\n'),
            'counter_bypass_zero': ('push %rbp\nmov %rsp, %rbp\nsub $16, %rsp\n'
                                    'movl $25, -4(%rbp)\njmp body\n'
                                    'movl $0, -4(%rbp)\njmp compare\n'
                                    'body:\nmov -4(%rbp), %edx\n'
                                    'lea payload(%rip), %rax\n'
                                    'movb (%rax,%rdx), %cl\nxorb $0x37, %cl\n'
                                    'movb %cl, (%rax,%rdx)\naddl $1, -4(%rbp)\n'
                                    'compare:\ncmpl $25, -4(%rbp)\njbe body\nleave\n'),
            'counter_mixed_width': ('push %rbp\nmov %rsp, %rbp\nsub $16, %rsp\n'
                                    'movabs $4294967296, %r9\nmov %r9, -4(%rbp)\n'
                                    'movl $0, -4(%rbp)\njmp compare\n'
                                    'body:\nmov -4(%rbp), %edx\n'
                                    'lea payload(%rip), %rax\n'
                                    'movb (%rax,%rdx), %cl\nxorb $0x37, %cl\n'
                                    'movb %cl, (%rax,%rdx)\naddl $1, -4(%rbp)\n'
                                    'compare:\ncmpq $25, -4(%rbp)\njbe body\nleave\n'),
            'counter_index_overwrite': ('push %rbp\nmov %rsp, %rbp\nsub $16, %rsp\n'
                                        'movl $0, -4(%rbp)\njmp compare\n'
                                        'body:\nmov -4(%rbp), %edx\nmov $0, %edx\n'
                                        'lea payload(%rip), %rax\nmovb (%rax,%rdx), %cl\n'
                                        'xorb $0x37, %cl\nmovb %cl, (%rax,%rdx)\n'
                                        'addl $1, -4(%rbp)\ncompare:\n'
                                        'cmpl $25, -4(%rbp)\njbe body\nleave\n'),
            'register_bypass_zero': ('mov $25, %esi\njmp body\nxor %esi, %esi\n'
                                     'body:\nmov %esi, %edx\nadd $1, %esi\n'
                                     'lea payload(%rip), %rax\n'
                                     'movb (%rax,%rdx), %cl\nxorb $0x37, %cl\n'
                                     'movb %cl, (%rax,%rdx)\n'
                                     'cmp $26, %esi\njne body\n'),
            'partial_index_write': ('push %rbp\nmov %rsp, %rbp\nsub $16, %rsp\n'
                                    'mov $256, %rdx\nmovl $0, -4(%rbp)\njmp compare\n'
                                    'body:\nmovb -4(%rbp), %dl\n'
                                    'lea payload(%rip), %rax\n'
                                    'movb (%rax,%rdx), %cl\nxorb $0x37, %cl\n'
                                    'movb %cl, (%rax,%rdx)\naddl $1, -4(%rbp)\n'
                                    'compare:\ncmpl $25, -4(%rbp)\n'
                                    'jbe body\nleave\n'),
            'partial_counter_zero': ('mov $256, %rsi\nxor %sil, %sil\n'
                                     'body:\nmov %esi, %edx\nadd $1, %esi\n'
                                     'lea payload(%rip), %rax\n'
                                     'movb (%rax,%rdx), %cl\nxorb $0x37, %cl\n'
                                     'movb %cl, (%rax,%rdx)\n'
                                     'cmp $26, %esi\njne body\n'),
            'register_indirect_bypass': ('lea body(%rip), %r9\njmp *%r9\n'
                                         'xor %esi, %esi\nbody:\n'
                                         'mov %esi, %edx\nadd $1, %esi\n'
                                         'lea payload(%rip), %rax\n'
                                         'movb (%rax,%rdx), %cl\nxorb $0x37, %cl\n'
                                         'movb %cl, (%rax,%rdx)\n'
                                         'cmp $26, %esi\njne body\n'),
            'register_skip_loop': ('jmp finish\nxor %esi, %esi\nbody:\n'
                                   'mov %esi, %edx\nadd $1, %esi\n'
                                   'lea payload(%rip), %rax\n'
                                   'movb (%rax,%rdx), %cl\nxorb $0x37, %cl\n'
                                   'movb %cl, (%rax,%rdx)\n'
                                   'cmp $26, %esi\njne body\nfinish:\n'),
        }
        for name, body in cases.items():
            with self.subTest(name=name):
                source = self.root / f'{name}.S'
                binary = self.root / name
                source.write_text(data + '.globl main\nmain:\n' + body +
                                  'xor %eax, %eax\nret\n.section .note.GNU-stack,"",@progbits\n')
                subprocess.run(['gcc', '-no-pie', '-o', str(binary), str(source)],
                               check=True, capture_output=True)
                rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
                self.assertEqual([row for row in rows if row['kind'] == 'xor'], [],
                                 (rows, warnings))
                self.assertIn('no plaintext inferred', ' '.join(warnings))

    def test_shifted_loop_does_not_claim_full_encoded_symbol(self):
        encoded = bytes(byte ^ 0x37 for byte in b'copper harbor violet route')
        source = self.root / 'shifted.S'
        binary = self.root / 'shifted'
        source.write_text('.section .data\n.globl payload\n.type payload, @object\n'
                          '.size payload, 27\npayload:\n.byte ' +
                          ','.join(map(str, encoded + b'\0')) +
                          '\n.section .text\n.globl main\nmain:\n'
                          'xor %esi, %esi\njmp compare\nbody:\nmov %esi, %edx\n'
                          'add $1, %esi\nlea payload+1(%rip), %rax\n'
                          'movb (%rax,%rdx), %cl\nxorb $0x37, %cl\n'
                          'movb %cl, (%rax,%rdx)\ncompare:\ncmp $26, %esi\n'
                          'jne body\nxor %eax, %eax\nret\n'
                          '.section .note.GNU-stack,"",@progbits\n')
        subprocess.run(['gcc', '-no-pie', '-o', str(binary), str(source)],
                       check=True, capture_output=True)
        rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
        self.assertEqual([row for row in rows if row['kind'] == 'xor'], [],
                         (rows, warnings))
        self.assertIn('no plaintext inferred', ' '.join(warnings))

    def test_xor_encoded_zero_before_terminator_is_preserved(self):
        phrase = b'copper harbor violet route7'
        key = 0x37
        encoded = bytes(byte ^ key for byte in phrase)
        self.assertEqual(encoded[-1], 0)
        source = ('volatile unsigned char payload[] = {' +
                  ','.join(map(str, encoded + b'\0')) + '};'
                  'int main(void){for(unsigned i=0;i<' + str(len(phrase)) +
                  ';i++)payload[i]^=0x37;return payload[0];}')
        for name, optimization, strip in (('encoded_zero', '-O0', False),
                                           ('encoded_zero_stripped', '-O2', True)):
            with self.subTest(name=name):
                binary = self.build(name, source, optimization=optimization, strip=strip)
                rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
                matches = [row for row in rows if row['kind'] == 'xor' and row['data'] == phrase]
                self.assertEqual(len(matches), 1, (rows, warnings))
                row = matches[0]
                self.assertEqual(row['key_hex'], f'{key:02x}')
                self.assertEqual(row['state'], 'candidate')
                offset = row['source_locator']['file_offset']
                self.assertEqual(row['source_locator']['length'], len(encoded))
                self.assertEqual(binary.read_bytes()[offset:offset + len(encoded) + 1],
                                 encoded + b'\0')

    def test_bounded_embedded_xor_span_has_slice_offset(self):
        for phrase in (b'copper harbor violet route', b'hello secret message in the data'):
            encoded = bytes(byte ^ 0x37 for byte in phrase)
            source = self.root / 'embedded.S'
            source.write_text('.section .data\n.globl bundle\n.type bundle, @object\n'
                              f'.size bundle, {len(encoded) + 2}\nbundle:\n.byte 18,' +
                              ','.join(map(str, encoded + b'\0')) +
                              '\n.section .text\n.globl main\nmain:\n'
                              'xor %esi, %esi\njmp compare\nbody:\nmov %esi, %edx\n'
                              'add $1, %esi\nlea bundle+1(%rip), %rax\n'
                              'movb (%rax,%rdx), %cl\nxorb $0x37, %cl\n'
                              'movb %cl, (%rax,%rdx)\ncompare:\n'
                              f'cmp ${len(encoded)}, %esi\n'
                              'jne body\nxor %eax, %eax\nret\n'
                              '.section .note.GNU-stack,"",@progbits\n')
            for label, strip in (('embedded', False), ('embedded_stripped', True)):
                name = f'{label}_{len(phrase)}'
                with self.subTest(name=name):
                    binary = self.root / name
                    command = ['gcc', '-no-pie', '-o', str(binary), str(source)]
                    if strip:
                        command.insert(2, '-s')
                    subprocess.run(command, check=True, capture_output=True)
                    offset = binary.read_bytes().find(encoded)
                    self.assertGreaterEqual(offset, 0)
                    rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
                    matches = [row for row in rows if row['kind'] == 'xor' and row['data'] == phrase]
                    self.assertEqual(len(matches), 1, (rows, warnings))
                    self.assertEqual([row for row in rows if row['kind'] == 'xor'], matches,
                                     (rows, warnings))
                    row = matches[0]
                    self.assertEqual(row['key_hex'], '37')
                    self.assertEqual(row['state'], 'candidate')
                    self.assertEqual(row['source_locator']['file_offset'], offset)
                    self.assertEqual(row['source_locator']['length'], len(phrase))
                    self.assertEqual(binary.read_bytes()[offset - 1], 18)
                    self.assertEqual(binary.read_bytes()[offset:offset + len(phrase) + 1],
                                     encoded + b'\0')

    def test_heldout_compiler_stack_placement(self):
        compiler = shutil.which('clang-16')
        if not compiler:
            self.skipTest('Clang 16 unavailable')
        phrase = b'CLANG_STACK_TEST'
        assignments = ''.join(f's[{index}]={byte};' for index, byte in enumerate(phrase + b'\0'))
        binary = self.build('clang_stack', 'int probe(void){volatile char s[32];'
                            + assignments + 'return s[1];} int main(void){return probe();}',
                            compiler=compiler, optimization='-O2')
        rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
        self.assertTrue(any(row['kind'] == 'stack' and row['data'] == phrase for row in rows),
                        (rows, warnings))

    def test_negative_arithmetic_and_random_constants_do_not_invent_plaintext(self):
        binary = self.build('negative', 'volatile unsigned long constants[] = '
                            '{0x138e8c037bba5105ULL,0x56201d854e249044ULL};'
                            'int main(void){unsigned long x=1;for(int i=0;i<8;i++)'
                            'x=(x*13+7)^constants[i%2];return (int)x;}')
        rows, warnings = rev_strings.inspect_strings(binary, timeout=5)
        self.assertEqual(rows, [])
        self.assertTrue(any('no plaintext inferred' in item for item in warnings))

    def test_floss_json_preserves_decoder_location_and_exact_encoding(self):
        doc = {'strings': {'stack_strings': [
            {'string': 'stack string', 'encoding': 'ASCII', 'function': 0x401000,
             'program_counter': 0x401020, 'frame_offset': 12, 'offset': 4}],
            'decoded_strings': [
                {'string': 'secret', 'encoding': 'UTF-16LE', 'address': 0x402000,
                 'address_type': 'GLOBAL', 'decoded_at': 0x401040,
                 'decoding_routine': 0x401080}]}}
        script = self.root / 'fake-floss'
        script.write_text('#!/usr/bin/env python3\nimport json\nprint(json.dumps(' + repr(doc) + '))\n')
        script.chmod(0o700)
        binary = self.build('floss_input', 'int main(void){return 0;}')
        rows, warnings = rev_strings.inspect_strings(binary, floss_path=str(script), timeout=5)
        self.assertFalse(any('FLOSS' in item for item in warnings), warnings)
        self.assertTrue(any(row['data'] == b'stack string' and
                            row['source_locator']['program_counter'] == 0x401020 for row in rows))
        self.assertTrue(any(row['data'] == 'secret'.encode('utf-16le') and
                            row['source_locator']['decoding_routine'] == 0x401080 for row in rows))

    def test_floss_child_relative_writes_stay_in_private_scratch(self):
        outside = self.root / 'outside'
        scratch = self.root / 'scratch'
        outside.mkdir()
        scratch.mkdir()
        script = self.root / 'relative-floss'
        script.write_text('#!/usr/bin/env python3\nimport json, os\nfrom pathlib import Path\n'
                          'Path("relative-write").write_text("probe")\n'
                          'print(json.dumps({"cwd": os.getcwd(), "strings": {}}))\n')
        script.chmod(0o700)
        binary = self.build('relative_input', 'int main(void){return 0;}')
        previous = Path.cwd()
        try:
            os.chdir(outside)
            document, warning = rev_strings._floss(binary, str(script),
                                                   time.monotonic() + 5, scratch)
        finally:
            os.chdir(previous)
        self.assertIsNone(warning)
        self.assertTrue(Path(document['cwd']).is_relative_to(scratch))
        self.assertFalse((outside / 'relative-write').exists())
        self.assertFalse(Path(document['cwd']).exists())

    def test_limits_bad_schema_and_unsupported_source(self):
        source = self.root / 'random'
        source.write_bytes(b'hello world')
        self.assertEqual(rev_strings.inspect_strings(source)[0], [])
        self.assertIn('unsupported', ' '.join(rev_strings.inspect_strings(source)[1]))
        with self.assertRaises(ValueError):
            rev_strings.inspect_strings(source, max_records=0)
        binary = self.build('limits', 'int main(void){return 0;}')
        self.assertEqual(rev_strings.inspect_strings(binary, max_source_bytes=1)[0], [])
        script = self.root / 'bad-floss'
        script.write_text('#!/usr/bin/env python3\nprint("{}")\n')
        script.chmod(0o700)
        self.assertIn('invalid FLOSS JSON', ' '.join(rev_strings.inspect_strings(
            binary, floss_path=str(script), timeout=5)[1]))
        script.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(2)\n')
        self.assertIn('FLOSS timed out', ' '.join(rev_strings.inspect_strings(
            binary, floss_path=str(script), timeout=0.05)[1]))
        rows, warnings = rev_strings._floss_records({'strings': {
            'stack_strings': [{'string': 'invented', 'encoding': 'ASCII'}]}}, 4)
        self.assertEqual(rows, [])
        self.assertIn('source address or offset', ' '.join(warnings))
        link = self.root / 'link'
        link.symlink_to(binary)
        self.assertEqual(rev_strings.inspect_strings(link)[0], [])
        malformed = self.root / 'malformed'
        malformed.write_bytes(b'\x7fELF' + b'\0' * 96)
        self.assertEqual(rev_strings.inspect_strings(malformed)[0], [])
        self.assertIn('malformed ELF', ' '.join(rev_strings.inspect_strings(malformed)[1]))

    def test_public_cli_reversing_and_auto_resume_preserve_candidate_lineage(self):
        stack = b'STACK_HELLO'
        plaintext = b'hello secret message in the data'
        encoded = bytes(byte ^ 0x37 for byte in plaintext)
        assignments = ''.join(f's[{index}]={byte};' for index, byte in enumerate(stack + b'\0'))
        source = ('volatile unsigned char encoded[] = {' +
                  ','.join(str(byte) for byte in encoded + b'\0') + '};'
                  'int probe(void){volatile char s[32];' + assignments + 'return s[1];}'
                  'int main(void){return probe()+encoded[0];}')
        binary = self.build('reversing', source)
        original = binary.read_bytes()

        def cli(*args):
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--json',
                                     *map(str, args)], capture_output=True, timeout=50,
                                    env={**os.environ, 'PATH': str(self.root)})
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            return json.loads(result.stdout)

        first = cli('analyze', binary, '--category', 'reversing', '--budget', '30',
                    '--runs-root', self.root / 'runs')
        run = Path(first['run'])
        manifest = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(manifest['coverage']['REV01']['status'], 'ran')
        self.assertEqual(manifest['coverage']['REV02']['status'], 'truncated')
        jobs = [job for job in manifest['jobs'] if job['adapter_id'] == 'rev-strings']
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['status'], 'complete')
        self.assertTrue(any('FLOSS backend unavailable' in item for item in jobs[0]['warnings']))
        records = json.loads(Path(jobs[0]['records_path']).read_text())
        self.assertTrue(any(row['kind'] == 'stack' and bytes.fromhex(row['data_hex']) == stack
                            for row in records))
        xor = next(row for row in records if row['kind'] == 'xor' and
                   bytes.fromhex(row['data_hex']) == plaintext)
        offset = xor['source_locator']['file_offset']
        self.assertEqual(original[offset:offset + len(encoded)], encoded)
        children = [item for item in manifest['artifacts'] if item['id'] in jobs[0]['child_ids']]
        self.assertTrue(any(Path(item['path']).read_bytes() == stack for item in children))
        self.assertTrue(any(Path(item['path']).read_bytes() == plaintext for item in children))
        self.assertTrue(all(any(edge['job_key'] == jobs[0]['key'] for edge in item['parents'])
                            for item in children))
        intel = [item for item in manifest['intelligence'] if item['job_id'] == jobs[0]['id']]
        self.assertTrue(any(item['source_locator'].get('file_offset') == offset and
                            item['source_locator']['candidate_state'] == 'candidate' for item in intel))
        self.assertEqual(binary.read_bytes(), original)

        cli('resume', run, '--budget', '10')
        resumed = json.loads((run / 'manifest.json').read_text())
        self.assertEqual(len([job for job in resumed['jobs'] if job['adapter_id'] == 'rev-strings']), 1)
        self.assertTrue(all(item['current'] for item in resumed['intelligence']
                            if item['job_id'] == jobs[0]['id']))
        binary.write_bytes(b'changed source\n')
        cli('resume', run, '--budget', '10')
        changed = json.loads((run / 'manifest.json').read_text())
        self.assertTrue(all(not item['current'] for item in changed['intelligence']
                            if item['job_id'] == jobs[0]['id']))
        self.assertTrue(all(not item['current'] for item in changed['artifacts']
                            if item['id'] in jobs[0]['child_ids']))

        binary.write_bytes(original)
        automatic = cli('analyze', binary, '--budget', '30',
                        '--runs-root', self.root / 'auto-runs')
        auto = json.loads((Path(automatic['run']) / 'manifest.json').read_text())
        self.assertEqual(len([job for job in auto['jobs'] if job['adapter_id'] == 'rev-strings']), 1)
        self.assertEqual(auto['coverage']['REV02']['status'], 'truncated')

    def test_doctor_reports_missing_floss_and_static_fallback(self):
        original = autosolve_setup.shutil.which
        with mock.patch.object(autosolve_setup.shutil, 'which',
                               side_effect=lambda name: None if name == 'floss' else original(name)), \
             mock.patch.object(rev_strings.shutil, 'which',
                               side_effect=lambda name: None if name == 'floss' else original(name)):
            report = autosolve_setup.doctor(['reversing'], self_test=True)
        operation = report['operations']['malware_reversing.obfuscated_strings']
        self.assertEqual(operation['functional_probe'], 'passed')
        self.assertEqual(operation['status'], 'partial')
        self.assertEqual(report['engines']['floss']['found'], False)
        self.assertIn('floss_missing', operation['reason'])

    def test_verified_managed_floss_precedes_path_and_tamper_blocks_fallback(self):
        root = self.root / 'export'
        installed = root / '.autosolve/engines/floss/floss'
        installed.parent.mkdir(parents=True)
        installed.write_bytes(b'fixture')
        for directory in (root / '.autosolve', root / '.autosolve/engines', installed.parent):
            directory.chmod(0o700)
        installed.chmod(0o700)
        with mock.patch.object(rev_strings, '__file__',
                               str(root / 'scripts/autosolve_lib/profiles/rev_strings.py')), \
             mock.patch.object(rev_strings.shutil, 'which', return_value='/usr/bin/floss'), \
             mock.patch('scripts.autosolve_lib.setup_env._floss_binary_matches', return_value=True):
            self.assertEqual(rev_strings.resolve_floss()[0], str(installed))
        with mock.patch.object(rev_strings, '__file__',
                               str(root / 'scripts/autosolve_lib/profiles/rev_strings.py')), \
             mock.patch.object(rev_strings.shutil, 'which', return_value='/usr/bin/floss'), \
             mock.patch('scripts.autosolve_lib.setup_env._floss_binary_matches', return_value=False):
            self.assertEqual(rev_strings.resolve_floss(), (None, 'floss_managed_binary_mismatch'))
        installed.unlink()
        installed.parent.rmdir()
        with mock.patch.object(rev_strings, '__file__',
                               str(root / 'scripts/autosolve_lib/profiles/rev_strings.py')), \
             mock.patch.object(rev_strings.shutil, 'which', return_value='./floss'):
            self.assertEqual(rev_strings.resolve_floss(),
                             (str(Path('./floss').absolute()), 'floss_unpinned_path'))

    def test_path_floss_survives_ordinary_unmanaged_autosolve_directory(self):
        root = self.root / 'export'
        autosolve = root / '.autosolve'
        autosolve.mkdir(parents=True)
        autosolve.chmod(0o755)
        module = str(root / 'scripts/autosolve_lib/profiles/rev_strings.py')
        with mock.patch.object(rev_strings, '__file__', module), \
             mock.patch.object(rev_strings.shutil, 'which', return_value='/usr/bin/floss'):
            self.assertEqual(rev_strings.resolve_floss(),
                             ('/usr/bin/floss', 'floss_unpinned_path'))
        autosolve.rmdir()
        outside = self.root / 'outside'
        outside.mkdir()
        autosolve.symlink_to(outside, target_is_directory=True)
        with mock.patch.object(rev_strings, '__file__', module), \
             mock.patch.object(rev_strings.shutil, 'which', return_value='/usr/bin/floss'):
            self.assertEqual(rev_strings.resolve_floss(),
                             (None, 'floss_managed_binary_mismatch'))

    def test_doctor_requires_obfuscated_marker_and_location(self):
        binary = self.root / 'floss'
        binary.write_bytes(b'fixture')
        marker = {'string': 'REV02_PROBE_42', 'encoding': 'ASCII',
                  'function': 0x401000, 'program_counter': 0x401020,
                  'frame_offset': 16}
        command = autosolve_setup._command

        def backend_help(argv, data=None, timeout=5, scratch_cwd=False):
            if argv[0] == str(binary):
                self.assertEqual(timeout, 15)
                self.assertTrue(scratch_cwd)
                return subprocess.CompletedProcess(argv, 0, b'--json -j' if '--help' in argv
                                                   else b'floss v3.2.0', b'')
            return command(argv, data, timeout=timeout, scratch_cwd=scratch_cwd)

        with mock.patch.object(rev_strings, 'resolve_floss',
                               return_value=(str(binary), 'floss_managed_verified')), \
             mock.patch.object(autosolve_setup, '_command', side_effect=backend_help), \
             mock.patch.object(rev_strings, '_floss', return_value=(
                 {'strings': {'stack_strings': [marker]}}, None)):
            operation, engine = autosolve_setup._rev_strings_probe(True)
        self.assertEqual((operation['status'], operation['functional_probe']), ('ready', 'passed'))
        self.assertEqual((engine['status'], engine['functional_probe']), ('ready', 'passed'))
        with mock.patch.object(rev_strings, 'resolve_floss',
                               return_value=(str(binary), 'floss_managed_verified')), \
             mock.patch.object(autosolve_setup, '_command', side_effect=backend_help), \
             mock.patch.object(rev_strings, '_floss', return_value=(
                 {'strings': {'stack_strings': [{**marker, 'program_counter': None}]}}, None)):
            operation, engine = autosolve_setup._rev_strings_probe(True)
        self.assertEqual((operation['status'], engine['status']), ('partial', 'partial'))
        with mock.patch.object(rev_strings, 'resolve_floss',
                               return_value=(str(binary), 'floss_unpinned_path')), \
             mock.patch.object(autosolve_setup, '_command', side_effect=backend_help), \
             mock.patch.object(rev_strings, '_floss', return_value=(
                 {'strings': {'stack_strings': [marker]}}, None)):
            operation, engine = autosolve_setup._rev_strings_probe(True)
        self.assertEqual((operation['status'], engine['status']), ('partial', 'partial'))
        self.assertEqual(engine['reason'], 'floss_unpinned_path')

    def test_unrelated_category_skips_floss_fingerprint(self):
        with mock.patch.object(core, '_rev_strings_fingerprint',
                               side_effect=AssertionError('FLOSS should not run')):
            fingerprints = core._current_adapter_fingerprints(
                time.monotonic() + 20, category='encoding')
        self.assertEqual(fingerprints['rev-strings'], [])

    def test_tampered_managed_floss_changes_resume_fingerprint(self):
        root = self.root / 'export'
        binary = root / '.autosolve/engines/floss/floss'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'fixture')
        for directory in (root / '.autosolve', root / '.autosolve/engines', binary.parent):
            directory.chmod(0o700)
        binary.chmod(0o700)
        with mock.patch.object(rev_strings, '__file__',
                               str(root / 'scripts/autosolve_lib/profiles/rev_strings.py')), \
             mock.patch.object(rev_strings.shutil, 'which', return_value=None), \
             mock.patch('scripts.autosolve_lib.setup_env._floss_binary_matches',
                        side_effect=(True, False)):
            before = core._rev_strings_fingerprint(time.monotonic() + 5)
            after = core._rev_strings_fingerprint(time.monotonic() + 5)
        self.assertNotEqual(before, after)

    def test_restored_backend_reactivates_only_matching_rev02_candidates(self):
        run = self.root / 'run'
        (run / 'jobs').mkdir(parents=True)
        source = self.build('restore', 'int main(void){return 0;}')
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        artifact = {'id': 'source', 'sha256': digest, 'path': str(source)}
        fingerprint = 'restored-backend'
        key = hashlib.sha256(f'source:{digest}:rev-strings.v1:{fingerprint}'.encode()).hexdigest()
        output = run / 'jobs' / 'old.rev-strings.json'
        output.write_text('[]')
        old = {'id': 'old', 'key': key, 'status': 'complete', 'child_ids': [],
               'records_path': str(output), 'records_sha256': hashlib.sha256(b'[]').hexdigest(),
               'coverage_status': 'ran', 'coverage_note': 'reused', 'warnings': []}
        previous = {'artifact_id': 'source', 'tag': 'REV02 string candidate',
                    'job_id': 'old', 'superseded': True}
        replacement = {'artifact_id': 'source', 'tag': 'REV02 string candidate',
                       'job_id': 'replacement', 'superseded': False}
        manifest = {'coverage': {'REV02': {'status': 'truncated', 'note': ''}},
                    'current_adapter_fingerprints': {'rev-strings': [fingerprint]},
                    'jobs': [old], 'intelligence': [previous, replacement],
                    'artifacts': [artifact], 'warnings': []}
        core._rev_strings_job(run, manifest, artifact, time.monotonic() + 5, deque(), 0)
        self.assertFalse(previous['superseded'])
        self.assertTrue(replacement['superseded'])
        self.assertEqual(manifest['coverage']['REV02']['status'], 'ran')

    def test_source_change_during_worker_rejects_publication(self):
        binary = self.build('changing', 'int main(void){return 0;}')
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        run = self.root / 'changing-run'
        (run / 'jobs').mkdir(parents=True)
        artifact = {'id': 'root', 'sha256': digest, 'path': str(binary),
                    'kind_evidence': 'elf', 'depth': 0}
        manifest = {'coverage': {'REV02': {'status': 'not scheduled', 'note': ''}},
                    'current_adapter_fingerprints': {'rev-strings': ['test-fingerprint']},
                    'jobs': [], 'intelligence': [], 'artifacts': [artifact],
                    'warnings': [], 'derived_bytes': 0}

        def change_source(*_):
            binary.write_bytes(b'changed during inspection')
            return [], []

        with mock.patch.object(core, '_run_rev_strings', side_effect=change_source):
            core._rev_strings_job(run, manifest, artifact, time.monotonic() + 5, deque(), 0)
        self.assertEqual(manifest['jobs'][0]['status'], 'failed')
        self.assertIn('source changed', manifest['jobs'][0]['warning'])
        self.assertEqual(manifest['jobs'][0]['child_ids'], [])
        self.assertEqual(manifest['intelligence'], [])


if __name__ == '__main__':
    unittest.main()
