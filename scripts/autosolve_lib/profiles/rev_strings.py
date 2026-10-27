"""Bounded, static recovery of executable stack and XOR string candidates."""

import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from collections import deque
from contextlib import contextmanager
from pathlib import Path

from .xor import recover_single_byte


MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_SCAN_BYTES = 1024 * 1024
MAX_TOOL_OUTPUT = 4 * 1024 * 1024
MAX_RECORDS = 64
MAX_STRING_BYTES = 4096


def resolve_floss() -> tuple[str | None, str]:
    """Prefer the verified toolkit binary; an invalid install blocks PATH fallback."""
    from ..setup_env import _floss_binary_matches

    root = Path(__file__).resolve().parents[3]
    directories = (root / '.autosolve', root / '.autosolve/engines',
                   root / '.autosolve/engines/floss')
    executable = directories[-1] / 'floss'
    try:
        for directory in directories:
            if directory.is_symlink():
                return None, 'floss_managed_binary_mismatch'
            if directory.exists():
                state = directory.stat(follow_symlinks=False)
                if (not stat.S_ISDIR(state.st_mode) or state.st_uid != os.geteuid() or
                        stat.S_IMODE(state.st_mode) != 0o700):
                    return None, 'floss_managed_binary_mismatch'
        if executable.is_symlink() or executable.exists() or directories[-1].exists():
            if (not executable.is_symlink() and _floss_binary_matches(executable) and
                    os.access(executable, os.X_OK)):
                return str(executable), 'floss_managed_verified'
            return None, 'floss_managed_binary_mismatch'
    except OSError:
        return None, 'floss_managed_binary_mismatch'
    fallback = shutil.which('floss')
    return (str(Path(fallback).absolute()), 'floss_unpinned_path') if fallback else (None, 'floss_missing')


@contextmanager
def _floss_temporary(scratch_dir: Path | None = None):
    from ..setup_env import _task_temporary

    root = Path(scratch_dir) if scratch_dir is not None else _task_temporary(
        Path(__file__).resolve().parents[3])
    if root.is_symlink() or not root.is_dir():
        raise OSError('FLOSS scratch directory is unavailable or symlinked')
    with tempfile.TemporaryDirectory(prefix='floss-', dir=root) as directory:
        yield Path(directory)


def _floss_environment(scratch: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({key: str(scratch) for key in ('TMPDIR', 'TMP', 'TEMP', 'HOME',
                                               'XDG_CACHE_HOME', 'FLOSS_CACHE_DIR')})
    env.update(FLOSS_SAVE_WORKSPACE='0', FLOSS_LOAD_VIV_WORKSPACE='0',
               FLOSS_CACHE_ENABLE='0', PYTHONDONTWRITEBYTECODE='1')
    return env


def _floss(path: Path, executable: str, deadline: float,
           scratch_dir: Path | None = None) -> tuple[dict | None, str | None]:
    with _floss_temporary(scratch_dir) as scratch:
        return _floss_process(path, executable, deadline, _floss_environment(scratch))


def _floss_process(path: Path, executable: str, deadline: float,
                   env: dict[str, str]) -> tuple[dict | None, str | None]:
    try:
        process = subprocess.Popen([executable, '-j', str(path)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True, env=env,
                                   cwd=env['TMPDIR'])
    except OSError as error:
        return None, f'FLOSS backend unavailable: {error}'
    selector = selectors.DefaultSelector()
    output, errors = bytearray(), bytearray()
    warning = None
    try:
        selector.register(process.stdout, selectors.EVENT_READ, output)
        selector.register(process.stderr, selectors.EVENT_READ, errors)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                warning = 'FLOSS timed out; analysis incomplete'
                break
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(errors) + len(chunk) > MAX_TOOL_OUTPUT:
                    warning = 'FLOSS output limit reached; analysis incomplete'
                    break
                key.data.extend(chunk)
            if warning:
                break
    finally:
        selector.close()
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
        process.stderr.close()
    if warning:
        return None, warning
    if process.returncode:
        detail = errors.decode('utf-8', 'replace').strip().splitlines()
        return None, f'FLOSS exited {process.returncode}: {(detail[0] if detail else "unknown error")[:200]}'
    try:
        document = json.loads(output)
        if not isinstance(document, dict) or not isinstance(document.get('strings'), dict):
            raise ValueError('missing strings object')
        return document, None
    except (ValueError, UnicodeDecodeError) as error:
        return None, f'invalid FLOSS JSON: {error}'


def _floss_records(document: dict, limit: int) -> tuple[list[dict], list[str]]:
    records, warnings = [], []
    groups = ('stack_strings', 'tight_strings', 'decoded_strings', 'language_strings')
    strings = document['strings']
    for group in groups:
        rows = strings.get(group, [])
        if not isinstance(rows, list):
            warnings.append(f'FLOSS {group} has an invalid shape')
            continue
        for row in rows:
            if len(records) >= limit:
                warnings.append('FLOSS string output limit reached')
                return records, warnings
            if not isinstance(row, dict) or not isinstance(row.get('string'), str):
                warnings.append(f'FLOSS {group} contains an invalid string')
                continue
            encoding = row.get('encoding')
            codec = {'ASCII': 'ascii', 'UTF-8': 'utf-8', 'UTF-16LE': 'utf-16le'}.get(encoding)
            if codec is None:
                warnings.append(f'FLOSS {group} has unsupported encoding')
                continue
            required = {'stack_strings': ('function', 'program_counter', 'frame_offset'),
                        'tight_strings': ('function', 'program_counter', 'frame_offset'),
                        'decoded_strings': ('address', 'decoded_at', 'decoding_routine'),
                        'language_strings': ('offset',)}[group]
            if any(not isinstance(row.get(key), int) or row[key] < 0 for key in required):
                warnings.append(f'FLOSS {group} lacks a valid source address or offset')
                continue
            try:
                data = row['string'].encode(codec)
            except UnicodeEncodeError:
                warnings.append(f'FLOSS {group} string cannot be represented exactly')
                continue
            if not 4 <= len(data) <= MAX_STRING_BYTES:
                warnings.append(f'FLOSS {group} string byte limit reached')
                continue
            locator = {'backend': 'floss'}
            if group in ('stack_strings', 'tight_strings'):
                fields = ('function', 'program_counter', 'frame_offset', 'offset')
            elif group == 'decoded_strings':
                fields = ('address', 'address_type', 'decoded_at', 'decoding_routine')
            else:
                fields = ('offset',)
            locator.update({key: row[key] for key in fields if isinstance(row.get(key), (int, str))})
            records.append({'kind': group.removesuffix('_strings'), 'data': data,
                            'text': row['string'], 'encoding': encoding,
                            'source_locator': locator, 'state': 'candidate',
                            'backend': 'floss'})
    return records, warnings


def _append_stack(stores: dict, records: list[dict], limit: int) -> None:
    for base, offsets in stores.items():
        start = previous = None
        run = []
        for offset, entry in sorted(offsets.items()):
            if previous is not None and offset != previous + 1:
                _stack_run(base, start, run, records, limit)
                run = []
                start = None
            if start is None:
                start = offset
            run.append(entry)
            previous = offset
        _stack_run(base, start, run, records, limit)


def _stack_run(base: str, start: int | None, run: list[tuple],
               records: list[dict], limit: int) -> None:
    if start is None or len(records) >= limit:
        return
    data = bytes(row[0] for row in run).split(b'\0', 1)[0]
    if not 6 <= len(data) <= MAX_STRING_BYTES or not all(32 <= byte <= 126 for byte in data):
        return
    if sum(chr(byte).isalpha() for byte in data) < 4:
        return
    evidence = sorted({(row[1], row[2]) for row in run[:len(data)]})
    locations = [row[0] for row in evidence]
    if any(row['data'] == data and
           row['source_locator'].get('instruction_file_offsets') == locations for row in records):
        return
    records.append({'kind': 'stack', 'data': data, 'text': data.decode('ascii'),
                    'encoding': 'ASCII', 'source_locator': {
                        'backend': 'literal-stack-stores', 'stack_base': base,
                        'stack_offset': start, 'instruction_file_offsets': locations,
                        'instruction_vaddrs': [row[1] for row in evidence]},
                    'state': 'candidate', 'backend': 'literal-stack-stores'})


def _append_sequence(sequence: list[tuple[int, int, int, int]],
                     records: list[dict], limit: int) -> None:
    # shortcut: instruction-order reconstruction requires a NUL terminator; nonterminated fragments need FLOSS.
    if len(sequence) < 7 or sequence[-1][0] != 0 or len(records) >= limit:
        return
    data = bytes(row[0] for row in sequence[:-1])
    if not 6 <= len(data) <= 128 or not all(32 <= byte <= 126 for byte in data):
        return
    if sum(chr(byte).isalpha() for byte in data) < 4:
        return
    locations = [row[1] for row in sequence[:-1]]
    if any(row['data'] == data and
           row['source_locator'].get('instruction_file_offsets') == locations for row in records):
        return
    records.append({'kind': 'stack', 'data': data, 'text': data.decode('ascii'),
                    'encoding': 'ASCII', 'source_locator': {
                        'backend': 'literal-store-sequence',
                        'instruction_file_offsets': locations,
                        'instruction_vaddrs': [row[2] for row in sequence[:-1]],
                        'stack_offsets_in_write_order': [row[3] for row in sequence[:-1]]},
                    'state': 'candidate', 'backend': 'literal-store-sequence'})


def _code_xor_candidates(encoded: bytes, start: int,
                         sites: list[dict]) -> list[dict]:
    direct = {}
    evidence = {}
    for site in sites:
        address, key, offset = site['address'], site['key'], site['offset']
        if not start <= address < start + len(encoded):
            continue
        if site['kind'] == 'direct':
            direct.setdefault(key, []).append((address, offset))
        elif site['index'] is not None and address == start:
            length = site['bound']
            if isinstance(length, int) and 16 <= length <= len(encoded) and \
                    not any(encoded[length:]):
                evidence[(key, length)] = offset
    for key, offsets in direct.items():
        addresses = {address for address, _ in offsets}
        length = len(addresses)
        if length >= 16 and addresses == set(range(start, start + length)) and \
                not any(encoded[length:]):
            evidence[(key, length)] = offsets[0][1]
    candidates = []
    for (key, length), offset in evidence.items():
        if key == 0:
            continue
        decoded = bytes(byte ^ key for byte in encoded[:length])
        words = decoded.split(b' ')
        if len(words) < 3 or not all(32 <= byte <= 126 for byte in decoded) or \
                sum(65 <= byte <= 90 or 97 <= byte <= 122 for byte in decoded) < len(decoded) * 0.6:
            continue
        candidates.append({'data': decoded, 'key_hex': f'{key:02x}',
                           'instruction_file_offset': offset})
    return candidates if len(candidates) == 1 else []


def _elf_records(path: Path, deadline: float, limit: int) -> tuple[list[dict], list[str]]:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
        from capstone.x86_const import (X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RBP,
                                        X86_REG_RSP, X86_REG_EBP, X86_REG_ESP, X86_REG_RIP)
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError as error:
        return [], [f'ELF string backend unavailable: {error}']

    records, warnings = [], []
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        if elf.header['e_machine'] not in ('EM_386', 'EM_X86_64') or not elf.little_endian:
            return [], ['unsupported ELF architecture for static string extraction']
        mode = CS_MODE_64 if elf.elfclass == 64 else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        md.detail = True
        bases = {X86_REG_RBP: 'bp', X86_REG_RSP: 'sp', X86_REG_EBP: 'bp', X86_REG_ESP: 'sp'}
        aliases = {name: parent for parent, names in {
            'rax': ('rax', 'eax', 'ax', 'al', 'ah'),
            'rbx': ('rbx', 'ebx', 'bx', 'bl', 'bh'),
            'rcx': ('rcx', 'ecx', 'cx', 'cl', 'ch'),
            'rdx': ('rdx', 'edx', 'dx', 'dl', 'dh'),
            'rsi': ('rsi', 'esi', 'si', 'sil'),
            'rdi': ('rdi', 'edi', 'di', 'dil'),
            'rbp': ('rbp', 'ebp', 'bp', 'bpl'),
            'rsp': ('rsp', 'esp', 'sp', 'spl'),
        }.items() for name in names}
        aliases.update({name: f'r{index}' for index in range(8, 16)
                        for name in (f'r{index}', f'r{index}d', f'r{index}w', f'r{index}b')})

        def family(register: int) -> str | None:
            name = md.reg_name(register)
            return aliases.get(name, name)

        def byte_lane(register: int) -> tuple[str | None, int]:
            return family(register), int(md.reg_name(register) in ('ah', 'bh', 'ch', 'dh'))

        def memory_key(operand):
            mem = operand.mem
            return family(mem.base), family(mem.index), mem.scale, mem.disp

        def loop_bound(history, site, branch):
            target = branch.operands[0].imm
            body = [row for row in history if target <= row.address <= branch.address]
            prior = [row for row in history if row.address < target]
            if not prior or not (target <= site['read'] < site['xor'] < site['store'] < branch.address):
                return None

            def safe_entry(initial_address):
                controls = [row for row in prior if row.address < initial_address and
                            row.mnemonic.startswith(('j', 'call', 'ret', 'loop'))]
                if not controls:
                    return len(history) < history.maxlen
                last = controls[-1]
                if last.mnemonic.startswith('ret'):
                    return True
                if last.mnemonic != 'jmp' or not last.operands or \
                        last.operands[0].type != X86_OP_IMM or \
                        last.operands[0].imm >= last.address:
                    return False
                after = [row for row in prior if last.address < row.address < initial_address]
                return not after or (
                    len(after) >= 2 and after[0].mnemonic == 'push' and
                    after[0].operands and after[0].operands[0].type == X86_OP_REG and
                    family(after[0].operands[0].reg) == 'rbp' and
                    after[1].mnemonic == 'mov' and len(after[1].operands) == 2 and
                    all(op.type == X86_OP_REG for op in after[1].operands) and
                    family(after[1].operands[0].reg) == 'rbp' and
                    family(after[1].operands[1].reg) == 'rsp' and
                    all(row.mnemonic in ('sub', 'nop', 'endbr64')
                        for row in after[2:]))
            compares = [row for row in body if site['store'] < row.address < branch.address and
                        row.mnemonic == 'cmp' and len(row.operands) == 2 and
                        row.operands[1].type == X86_OP_IMM]
            if len(compares) != 1:
                return None
            compare = compares[0]
            if any(row.mnemonic.startswith(('j', 'call', 'ret', 'loop'))
                   for row in body if row.address < branch.address):
                return None
            if any('rflags' in {md.reg_name(reg) for reg in row.regs_access()[1]}
                   for row in body if compare.address < row.address < branch.address):
                return None
            bound = compare.operands[1].imm + int(branch.mnemonic in ('jbe', 'jna'))
            if not 16 <= bound <= 256:
                return None
            index = site['index']
            if branch.mnemonic in ('jne', 'jnz') and compare.operands[0].type == X86_OP_REG and \
                    compare.operands[0].size >= 4:
                counter = family(compare.operands[0].reg)
                copies = [row for row in body if row.address < site['read'] and
                          row.mnemonic == 'mov' and len(row.operands) == 2 and
                          row.operands[0].type == X86_OP_REG and
                          row.operands[0].size >= 4 and
                          family(row.operands[0].reg) == index and
                          row.operands[1].type == X86_OP_REG and
                          row.operands[1].size >= 4 and
                          family(row.operands[1].reg) == counter]
                if len(copies) != 1:
                    return None
                copy = copies[0]
                increments = [row for row in body if copy.address < row.address < site['read'] and
                              row.mnemonic == 'add' and len(row.operands) == 2 and
                              row.operands[0].type == X86_OP_REG and
                              row.operands[0].size >= 4 and
                              family(row.operands[0].reg) == counter and
                              row.operands[1].type == X86_OP_IMM and row.operands[1].imm == 1]
                if len(increments) != 1 or any(
                        counter in {family(reg) for reg in row.regs_access()[1]}
                        for row in body if row.address != increments[0].address):
                    return None
                initial = [row for row in prior if counter in
                           {family(reg) for reg in row.regs_access()[1]}]
                if not initial:
                    return None
                zero = initial[-1]
                if not (zero.mnemonic == 'xor' and len(zero.operands) == 2 and
                        all(op.type == X86_OP_REG and op.size >= 4 and
                            family(op.reg) == counter
                            for op in zero.operands)):
                    return None
                if any(row.mnemonic not in ('lea', 'nop') and not (
                        row.mnemonic == 'jmp' and row.operands and
                        row.operands[0].type == X86_OP_IMM and
                        row.operands[0].imm == compare.address)
                       for row in prior if row.address > zero.address):
                    return None
                if not safe_entry(zero.address):
                    return None
                if any(index in {family(reg) for reg in row.regs_access()[1]}
                       for row in body if copy.address < row.address <= site['store']):
                    return None
                return bound
            if branch.mnemonic not in ('jbe', 'jna') or \
                    compare.operands[0].type != X86_OP_MEM or compare.operands[0].size < 4:
                return None
            slot = memory_key(compare.operands[0])
            slot_width = compare.operands[0].size
            loads = [row for row in body if row.address < site['read'] and
                     row.mnemonic == 'mov' and len(row.operands) == 2 and
                     row.operands[0].type == X86_OP_REG and
                     row.operands[0].size >= 4 and
                     family(row.operands[0].reg) == index and
                     row.operands[1].type == X86_OP_MEM and
                     row.operands[1].size == slot_width and memory_key(row.operands[1]) == slot]
            increments = [row for row in body if site['store'] < row.address < compare.address and
                          row.mnemonic == 'add' and len(row.operands) == 2 and
                          row.operands[0].type == X86_OP_MEM and
                          row.operands[0].size == slot_width and memory_key(row.operands[0]) == slot and
                          row.operands[1].type == X86_OP_IMM and row.operands[1].imm == 1]
            if len(loads) != 1 or len(increments) != 1:
                return None
            if any(index in {family(reg) for reg in row.regs_access()[1]}
                   for row in body if loads[0].address < row.address < site['read']):
                return None
            slot_writes = [row for row in body if row.operands and
                           row.operands[0].type == X86_OP_MEM and
                           memory_key(row.operands[0]) == slot and row.mnemonic != 'cmp']
            if len(slot_writes) != 1:
                return None
            initial = [row for row in prior if row.operands and
                       row.operands[0].type == X86_OP_MEM and memory_key(row.operands[0]) == slot and
                       row.mnemonic == 'mov' and len(row.operands) == 2 and
                       row.operands[0].size == slot_width and
                       row.operands[1].type == X86_OP_IMM and row.operands[1].imm == 0]
            prior_writes = [row for row in prior if row.operands and
                            row.operands[0].type == X86_OP_MEM and
                            memory_key(row.operands[0]) == slot and row.mnemonic != 'cmp']
            if not initial or prior_writes[-1].address != initial[-1].address:
                return None
            if not safe_entry(initial[-1].address):
                return None
            after_init = [row for row in prior if row.address > initial[-1].address]
            if len(after_init) != 1 or after_init[0].mnemonic != 'jmp' or \
                    not after_init[0].operands or after_init[0].operands[0].type != X86_OP_IMM or \
                    after_init[0].operands[0].imm != compare.address:
                return None
            slot_registers = {slot[0], slot[1]} - {None, ''}
            if any(slot_registers.intersection({family(reg) for reg in row.regs_access()[1]})
                   for row in body):
                return None
            reloads = []
            if any(index in {family(reg) for reg in row.regs_access()[1]}
                   for row in body if site['read'] <= row.address < site['store']):
                reloads = [row for row in body if site['xor'] < row.address < site['store'] and
                           row.mnemonic == 'mov' and len(row.operands) == 2 and
                           row.operands[0].type == X86_OP_REG and
                           row.operands[0].size >= 4 and
                           family(row.operands[0].reg) == index and
                           row.operands[1].type == X86_OP_MEM and
                           row.operands[1].size == slot_width and memory_key(row.operands[1]) == slot]
                if len(reloads) != 1:
                    return None
                index_writes = [row for row in body if site['xor'] < row.address < site['store'] and
                                index in {family(reg) for reg in row.regs_access()[1]}]
                if not index_writes or index_writes[-1].address != reloads[0].address:
                    return None
            allowed_memory = {loads[0].address, site['read'], site['store'],
                              increments[0].address, compare.address}
            allowed_memory.update(row.address for row in reloads)
            if any(row.mnemonic not in ('mov', 'movzx', 'xor', 'add', 'cmp',
                                        'lea', 'nop', 'jbe', 'jna') or
                   (row.mnemonic != 'lea' and row.address not in allowed_memory and
                    any(op.type == X86_OP_MEM for op in row.operands))
                   for row in body):
                return None
            return bound

        scanned = 0
        xor_sites = []
        for section in elf.iter_sections():
            if time.monotonic() >= deadline:
                warnings.append('static string scan timed out')
                break
            size = section['sh_size']
            flags = section['sh_flags']
            if not flags & 0x4 or flags & 0x800 or not size:  # skip compressed executable sections
                continue
            if scanned + size > MAX_SCAN_BYTES:
                warnings.append('executable byte scan limit reached')
                break
            scanned += size
            blob = section.data()
            stores: dict[str, dict[int, tuple[int, int, int]]] = {}
            sequence = []
            since_store = 0
            previous = pending = None
            address_registers = {}
            recent = deque(maxlen=96)
            section_sites_start = len(xor_sites)
            for instruction in md.disasm(blob, section['sh_addr']):
                if time.monotonic() >= deadline or len(records) >= limit:
                    break
                operands = instruction.operands
                recent.append(instruction)
                written = {family(register) for register in instruction.regs_access()[1]}
                if pending:
                    signature, address, key, xor_offset, remaining, tracked, outputs, index, read, xor = pending
                    changed = written.intersection(tracked)
                    if changed and not (len(changed) == 1 and instruction.mnemonic == 'lea' and
                                        len(operands) == 2 and operands[0].type == X86_OP_REG and
                                        family(operands[0].reg) in changed and
                                        operands[1].type == X86_OP_MEM and
                                        operands[1].mem.base == X86_REG_RIP and
                                        not operands[1].mem.index and
                                        instruction.address + instruction.size +
                                        operands[1].mem.disp == tracked[family(operands[0].reg)]):
                        pending = None
                    if pending:
                        copied = (byte_lane(operands[0].reg) if instruction.mnemonic == 'mov' and
                                  len(operands) == 2 and operands[0].type == X86_OP_REG and
                                  operands[1].type == X86_OP_REG and
                                  byte_lane(operands[1].reg) in outputs else None)
                        outputs = {output for output in outputs if output[0] not in written}
                        if copied:
                            outputs.add(copied)
                        if not outputs:
                            pending = None
                    if pending and instruction.mnemonic == 'mov' and len(operands) == 2 and \
                            operands[0].type == X86_OP_MEM and operands[0].size == 1 and \
                            operands[1].type == X86_OP_REG and \
                            byte_lane(operands[1].reg) in outputs:
                        mem = operands[0].mem
                        if (mem.base, mem.index, mem.scale, mem.disp) == signature and \
                                len(xor_sites) < 4096:
                            xor_sites.append({'address': address, 'key': key, 'offset': xor_offset,
                                              'kind': 'loop', 'index': index, 'bound': None,
                                              'read': read, 'xor': xor, 'store': instruction.address})
                            pending = None
                    if pending:
                        pending = (signature, address, key, xor_offset,
                                   remaining - 1, tracked, outputs, index, read, xor) if remaining > 1 else None
                if instruction.mnemonic == 'xor' and len(operands) == 2 and \
                        operands[1].type == X86_OP_IMM and 0 < operands[1].imm < 256:
                    key = operands[1].imm
                    xor_offset = section['sh_offset'] + instruction.address - section['sh_addr']
                    if operands[0].type == X86_OP_MEM and operands[0].size == 1 and \
                            len(xor_sites) < 4096:
                        mem = operands[0].mem
                        address = (instruction.address + instruction.size + mem.disp
                                   if mem.base == X86_REG_RIP else mem.disp)
                        if mem.base in (0, X86_REG_RIP) and not mem.index:
                            xor_sites.append({'address': address, 'key': key, 'offset': xor_offset,
                                              'kind': 'direct', 'index': None, 'bound': None})
                    elif operands[0].type == X86_OP_REG and previous and \
                            previous.mnemonic in ('mov', 'movzx') and len(previous.operands) == 2 and \
                            previous.operands[0].type == X86_OP_REG and \
                            previous.operands[0].reg == operands[0].reg and \
                            previous.operands[1].type == X86_OP_MEM and \
                            previous.operands[1].size == 1:
                        mem = previous.operands[1].mem
                        tracked = {name: address_registers[name]
                                   for name in (family(mem.base), family(mem.index))
                                   if name in address_registers}
                        unknown = {family(register) for register in (mem.base, mem.index)
                                   if register not in (0, X86_REG_RIP) and
                                   family(register) not in tracked}
                        if len(tracked) <= 1 and len(unknown) <= 1 and mem.scale == 1 and \
                                family(operands[0].reg) not in tracked:
                            address = mem.disp + next(iter(tracked.values()), 0)
                            pending = ((mem.base, mem.index, mem.scale, mem.disp),
                                       address, key, xor_offset, 4, tracked,
                                       {byte_lane(operands[0].reg)},
                                       next(iter(unknown), None), previous.address,
                                       instruction.address)
                for register in written:
                    address_registers.pop(register, None)
                if instruction.mnemonic == 'lea' and len(operands) == 2 and \
                        operands[0].type == X86_OP_REG and operands[1].type == X86_OP_MEM and \
                        operands[1].mem.base == X86_REG_RIP and not operands[1].mem.index:
                    address_registers[family(operands[0].reg)] = (instruction.address +
                                                                   instruction.size + operands[1].mem.disp)
                previous = instruction
                if instruction.mnemonic.startswith(('ret', 'jmp', 'j', 'call')):
                    if instruction.mnemonic.startswith('j') and instruction.mnemonic != 'jmp' and \
                            operands and operands[0].type == X86_OP_IMM and \
                            operands[0].imm < instruction.address:
                        for site in reversed(xor_sites[section_sites_start:]):
                            if site.get('xor', instruction.address) < operands[0].imm:
                                break
                            if site['kind'] == 'loop' and site['index'] is not None and \
                                    site['bound'] is None and \
                                    operands[0].imm <= site['xor'] < instruction.address:
                                site['bound'] = loop_bound(recent, site, instruction)
                    _append_stack(stores, records, limit)
                    _append_sequence(sequence, records, limit)
                    stores = {}
                    sequence = []
                    since_store = 0
                    pending = None
                    address_registers.clear()
                    continue
                since_store += 1
                if since_store > 64:
                    _append_stack(stores, records, limit)
                    stores = {}
                    since_store = 0
                operands = instruction.operands
                if instruction.mnemonic != 'mov' or len(operands) != 2 or \
                        operands[0].type != X86_OP_MEM or operands[1].type != X86_OP_IMM:
                    _append_sequence(sequence, records, limit)
                    sequence = []
                    continue
                memory = operands[0].mem
                if memory.base not in bases or memory.index or not 1 <= operands[0].size <= 8:
                    _append_sequence(sequence, records, limit)
                    sequence = []
                    continue
                width = operands[0].size
                value = (operands[1].imm & ((1 << (width * 8)) - 1)).to_bytes(width, 'little')
                offset = section['sh_offset'] + instruction.address - section['sh_addr']
                entries = stores.setdefault(bases[memory.base], {})
                for index, byte in enumerate(value):
                    entries[memory.disp + index] = (byte, offset, instruction.address)
                if width == 1 and (not sequence or len(sequence) < 129):
                    sequence.append((value[0], offset, instruction.address, memory.disp))
                else:
                    _append_sequence(sequence, records, limit)
                    sequence = []
                since_store = 0
            _append_stack(stores, records, limit)
            _append_sequence(sequence, records, limit)
            if len(records) >= limit:
                warnings.append('static stack string output limit reached')
                return records, warnings
        data_sections = {index: section for index, section in enumerate(elf.iter_sections())
                         if section['sh_type'] == 'SHT_PROGBITS' and section['sh_flags'] & 0x2
                         and not section['sh_flags'] & 0x800
                         and not section['sh_flags'] & 0x4}
        blocks = []
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if time.monotonic() >= deadline:
                    warnings.append('static string scan timed out')
                    return records, warnings
                if symbol['st_info']['type'] != 'STT_OBJECT' or not isinstance(symbol['st_shndx'], int):
                    continue
                target = data_sections.get(symbol['st_shndx'])
                size = symbol['st_size']
                if target is None or not 16 <= size <= 256:
                    continue
                offset = target['sh_offset'] + symbol['st_value'] - target['sh_addr']
                if target['sh_offset'] <= offset and offset + size <= target['sh_offset'] + target['sh_size']:
                    blocks.append((offset, size, symbol.name, symbol['st_value']))
        has_symbols = bool(blocks)
        symbol_starts = {address for _, _, _, address in blocks}
        linked_blocks = set()
        data_cache = {}
        for site in xor_sites:
            bound = site.get('bound')
            if site['kind'] != 'loop' or site['index'] is None or \
                    not isinstance(bound, int) or not 16 <= bound <= 256 or \
                    site['address'] in symbol_starts:
                continue
            for section in data_sections.values():
                relative = site['address'] - section['sh_addr']
                if not 0 <= relative or relative + bound > section['sh_size'] or \
                        section['sh_size'] > MAX_SCAN_BYTES:
                    continue
                section_offset = section['sh_offset']
                if section_offset not in data_cache:
                    data_cache[section_offset] = section.data()
                data = data_cache[section_offset]
                end = relative + bound
                if (end < len(data) and data[end] == 0) or \
                        relative == 0 or data[relative - 1] == 0:
                    linked_blocks.add((section['sh_offset'] + relative, bound, None,
                                       site['address']))
                break
            if len(linked_blocks) >= 128:
                warnings.append('XOR linked block limit reached')
                break
        blocks = sorted(linked_blocks) + blocks
        if not has_symbols:
            for section in data_sections.values():
                if section['sh_size'] > MAX_SCAN_BYTES:
                    warnings.append('data byte scan limit reached')
                    continue
                for match in re.finditer(rb'[^\x00]+', section.data()):
                    if not 16 <= len(match.group()) <= 256:
                        continue
                    blocks.append((section['sh_offset'] + match.start(), len(match.group()), None,
                                   section['sh_addr'] + match.start()))
                    if len(blocks) >= 128:
                        warnings.append('XOR data block limit reached')
                        break
        seen_blocks = set()
        for offset, length, symbol, address in blocks[:128]:
            if (offset, length) in seen_blocks:
                continue
            seen_blocks.add((offset, length))
            if time.monotonic() >= deadline:
                warnings.append('static string scan timed out')
                break
            if len(records) >= limit:
                warnings.append('XOR string output limit reached')
                break
            stream.seek(offset)
            raw = stream.read(length)
            encoded = raw.rstrip(b'\0')
            candidates = _code_xor_candidates(raw, address, xor_sites)
            if not candidates and any(start >= offset and start + size <= offset + length and
                                      (start, size) != (offset, length)
                                      for start, size, _, _ in linked_blocks):
                continue
            for candidate in candidates or recover_single_byte(encoded, max_candidates=1):
                if candidate['key_hex'] == '00' or candidate['data'] == raw[:len(candidate['data'])]:
                    continue
                locator = {'backend': 'symbol-data-xor' if symbol else 'data-run-xor',
                           'file_offset': offset, 'length': len(candidate['data']), 'symbol': symbol}
                if 'instruction_file_offset' in candidate:
                    locator['xor_instruction_file_offset'] = candidate['instruction_file_offset']
                records.append({'kind': 'xor', 'data': candidate['data'],
                                'text': candidate['data'].decode('ascii', 'replace'),
                                'encoding': 'ASCII', 'key_hex': candidate['key_hex'],
                                'source_locator': locator, 'state': 'candidate',
                                'backend': 'single-byte-xor'})
    return records, warnings


def inspect_strings(path: Path, *, max_source_bytes: int = MAX_SOURCE_BYTES,
                    max_records: int = MAX_RECORDS, timeout: float = 20,
                    floss_path: str | None = None,
                    scratch_dir: Path | None = None) -> tuple[list[dict], list[str]]:
    """Return exact decoded candidate bytes and source locators; never execute the input."""
    if not 0 < max_source_bytes <= MAX_SOURCE_BYTES or not 0 < max_records <= MAX_RECORDS or not 0 < timeout <= 120:
        raise ValueError('REV02 limits must be positive and bounded')
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        return [], ['executable source unavailable or symlinked']
    if path.stat().st_size > max_source_bytes:
        return [], ['executable source byte limit reached']
    with path.open('rb') as stream:
        magic = stream.read(4)
    if magic != b'\x7fELF' and magic[:2] != b'MZ':
        return [], ['unsupported executable format for REV02']
    deadline = time.monotonic() + timeout
    records, warnings = [], []
    executable, source = ((str(Path(floss_path).absolute()), 'floss_explicit_unpinned')
                          if floss_path else resolve_floss())
    if executable:
        document, warning = _floss(path.resolve(), executable, deadline, scratch_dir)
        if warning:
            warnings.append(warning)
        elif document is not None:
            found, notices = _floss_records(document, max_records)
            records.extend(found)
            warnings.extend(notices)
        if source == 'floss_unpinned_path':
            warnings.append('FLOSS PATH backend is unpinned')
    else:
        warnings.append(f'FLOSS backend unavailable ({source}); decoded and compiler-specific string coverage incomplete')
    if magic == b'\x7fELF' and time.monotonic() < deadline and len(records) < max_records:
        try:
            from elftools.common.exceptions import ELFError
        except ImportError:
            ELFError = ValueError
        try:
            found, notices = _elf_records(path, deadline, max_records - len(records))
            records.extend(found)
            warnings.extend(notices)
        except (OSError, ValueError, EOFError, IndexError, KeyError, ELFError) as error:
            warnings.append(f'malformed ELF string source: {type(error).__name__}: {error}')
    if not records:
        warnings.append('no supported obfuscated strings recovered; no plaintext inferred')
    return records[:max_records], warnings
