"""REV07 explicit execution and bounded checker evidence."""

import hashlib
import mmap
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.autosolve_lib.profiles import checker, elf


@unittest.skipUnless(shutil.which('gcc'), 'gcc is unavailable')
class CheckerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def build(self, name, source):
        source_file = self.root / f'{name}.c'
        binary = self.root / name
        source_file.write_text(source)
        subprocess.run(['gcc', '-O0', '-fno-pie', '-no-pie', '-o', str(binary),
                        str(source_file)], check=True, capture_output=True)
        return binary

    def test_stdin_candidate_requires_execution_gate_and_replay(self):
        binary = self.build('stdin_check', '''#include <stdio.h>
int main(void) { char s[8] = {0};
  if (!fgets(s, sizeof s, stdin)) return 2;
  if (s[0]=='K' && s[1]=='7' && s[2]=='Q' && s[3]=='!') { puts("WIN"); return 0; }
  puts("LOSE"); return 1;
}''')
        hints = {'channel': 'stdin', 'length': 4, 'find': {'stdout': 'WIN'},
                 'avoid': {'stdout': 'LOSE'}}
        before = hashlib.sha256(binary.read_bytes()).hexdigest()
        skipped, _ = checker.inspect_checker(binary, hints)
        self.assertEqual(skipped['status'], 'skipped_execution')
        self.assertNotIn('candidate_hex', skipped)
        candidate, _ = checker.inspect_checker(binary, hints, execute_local=True)
        self.assertEqual(candidate['status'], 'candidate', candidate)
        self.assertEqual(bytes.fromhex(candidate['candidate_hex']), b'K7Q!')
        self.assertFalse(candidate['replay']['attempted'])
        verified, _ = checker.inspect_checker(binary, hints, execute_local=True,
                                              replay=True)
        self.assertEqual(verified['status'], 'validated_input', verified)
        self.assertEqual(verified['replay']['returncode'], 0)
        self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), before)

    def test_argv_heldout_input_and_success_text(self):
        binary = self.build('argv_check', '''#include <stdio.h>
int main(int argc, char **argv) { if (argc != 2) return 2;
  if (argv[1][0]=='9' && argv[1][1]=='x' && argv[1][2]=='R') {
    puts("PASS-ARG"); return 0; }
  puts("FAIL-ARG"); return 1;
}''')
        hints = {'channel': 'argv', 'length': 3, 'find': {'stdout': 'PASS-ARG'},
                 'avoid': {'stdout': 'FAIL-ARG'}}
        result, warnings = checker.inspect_checker(binary, hints, execute_local=True,
                                                   replay=True)
        self.assertEqual(result['status'], 'validated_input', (result, warnings))
        self.assertEqual(bytes.fromhex(result['candidate_hex']), b'9xR')

    def test_exhausted_unsat_and_invalid_hints(self):
        binary = self.build('unsat_check', '''#include <stdio.h>
int main(int argc, char **argv) { if (argc != 2) return 2;
  if (argv[1][0]=='A' && argv[1][0]=='B') puts("WIN");
  else puts("LOSE"); return 0; }
''')
        hints = {'channel': 'argv', 'length': 1, 'find': {'stdout': 'WIN'},
                 'avoid': {'stdout': 'LOSE'}}
        result, _ = checker.inspect_checker(binary, hints, execute_local=True)
        self.assertEqual(result['status'], 'unsat_under_model', result)
        for bad in ({'channel': 'stdin', 'length': 0, 'find': {'stdout': 'WIN'}},
                    {'channel': 'argv', 'length': 1, 'find': {'python': 'eval(1)'}},
                    {'channel': 'argv', 'length': 1, 'find': {'address': '0x401000'}}):
            with self.assertRaises(ValueError):
                checker.inspect_checker(binary, bad, execute_local=True)

    def test_tiny_step_budget_is_incomplete_not_unsat(self):
        binary = self.build('budget_check', '''#include <stdio.h>
int main(int argc, char **argv) { if (argc < 2) return 2;
  if (argv[1][0]=='A') puts("WIN"); else puts("LOSE"); return 0; }
''')
        result, _ = checker.inspect_checker(
            binary, {'channel': 'argv', 'length': 1, 'find': {'stdout': 'WIN'}},
            execute_local=True, max_steps=1)
        self.assertEqual(result['status'], 'incomplete', result)

    def test_unknown_native_syscall_is_incomplete(self):
        binary = self.build('syscall_check', '''#include <stdio.h>
int main(void) { long result;
  __asm__ volatile("mov $999999, %%rax; syscall" : "=a"(result) :: "rcx", "r11");
  puts("WIN"); return result == 0 ? 0 : 1; }
''')
        result, _ = checker.inspect_checker(
            binary, {'channel': 'stdin', 'length': 1, 'find': {'stdout': 'WIN'}},
            execute_local=True)
        self.assertEqual(result['status'], 'incomplete', result)
        self.assertIn('syscall', result['reason'])

    def test_avoid_condition_discards_path_before_later_win(self):
        binary = self.build('avoid_check', '''#include <stdio.h>
int main(void) { puts("LOSE"); puts("WIN"); return 0; }
''')
        result, _ = checker.inspect_checker(
            binary, {'channel': 'stdin', 'length': 1,
                     'find': {'stdout': 'WIN'}, 'avoid': {'stdout': 'LOSE'}},
            execute_local=True)
        self.assertEqual(result['status'], 'unsat_under_model', result)

    def test_address_avoid_prunes_active_state(self):
        binary = self.build('address_avoid', '''#include <stdio.h>
int main(void) { puts("WIN"); return 0; }
''')
        report, _ = elf.inspect_elf(binary)
        main_address = next(row['vaddr'] for row in report['symbols'] if row['name'] == 'main')
        result, _ = checker.inspect_checker(
            binary, {'channel': 'stdin', 'length': 1,
                     'find': {'stdout': 'WIN'}, 'avoid': {'address': main_address}},
            execute_local=True)
        self.assertEqual(result['status'], 'unsat_under_model', result)

    def test_address_find_replay_stays_candidate_without_observable_oracle(self):
        binary = self.build('address_find', '''#include <stdio.h>
__attribute__((noinline)) void win(void) { puts("WIN"); }
int main(int argc, char **argv) { if (argc==2 && argv[1][0]=='Z') win(); return 0; }
''')
        report, _ = elf.inspect_elf(binary)
        win_address = next(row['vaddr'] for row in report['symbols'] if row['name'] == 'win')
        result, _ = checker.inspect_checker(
            binary, {'channel': 'argv', 'length': 1, 'find': {'address': win_address}},
            execute_local=True, replay=True)
        self.assertEqual(result['status'], 'candidate', result)
        self.assertEqual(bytes.fromhex(result['candidate_hex']), b'Z')
        self.assertTrue(result['replay']['attempted'])

    def test_replay_rejects_success_text_on_nonzero_exit(self):
        binary = self.build('false_success', '''#include <stdio.h>
int main(int argc, char **argv) { puts("WIN"); return 1; }
''')
        result, _ = checker.inspect_checker(
            binary, {'channel': 'argv', 'length': 1, 'find': {'stdout': 'WIN'}},
            execute_local=True, replay=True)
        self.assertEqual(result['status'], 'replay_failed', result)

    def test_large_untouched_parent_mapping_does_not_exhaust_worker_limit(self):
        binary = self.build('mapped_parent', '''#include <stdio.h>
int main(int argc, char **argv) {
  if (argc == 2 && argv[1][0] == 'M') { puts("MAP_WIN"); return 0; }
  puts("MAP_LOSE"); return 1;
}''')
        hints = {'channel': 'argv', 'length': 1,
                 'find': {'stdout': 'MAP_WIN'}, 'avoid': {'stdout': 'MAP_LOSE'}}
        try:
            mapping = mmap.mmap(-1, 3 * 1024**3, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                                prot=mmap.PROT_READ | mmap.PROT_WRITE)
        except (OSError, ValueError) as error:
            self.skipTest(f'untouched virtual mapping unavailable: {type(error).__name__}')
        with mapping:
            result, _ = checker.inspect_checker(binary, hints, execute_local=True,
                                                replay=True, timeout=30)
        self.assertEqual(result['status'], 'validated_input', result)
        self.assertEqual(bytes.fromhex(result['candidate_hex']), b'M')


if __name__ == '__main__':
    unittest.main()
