"""Bounded, static recovery of executable stack and XOR string candidates."""

import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path

from .xor import recover_single_byte


MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_SCAN_BYTES = 1024 * 1024
MAX_TOOL_OUTPUT = 4 * 1024 * 1024
MAX_RECORDS = 64
MAX_STRING_BYTES = 4096


def _floss(path: Path, executable: str, deadline: float) -> tuple[dict | None, str | None]:
    env = os.environ.copy()
    env['FLOSS_SAVE_WORKSPACE'] = '0'
    env['FLOSS_LOAD_VIV_WORKSPACE'] = '0'
    try:
        process = subprocess.Popen([executable, '-j', str(path)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True, env=env)
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


def _elf_records(path: Path, deadline: float, limit: int) -> tuple[list[dict], list[str]]:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
        from capstone.x86_const import (X86_OP_IMM, X86_OP_MEM, X86_REG_RBP, X86_REG_RSP,
                                        X86_REG_EBP, X86_REG_ESP)
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
        scanned = 0
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
            for instruction in md.disasm(blob, section['sh_addr']):
                if time.monotonic() >= deadline or len(records) >= limit:
                    break
                if instruction.mnemonic.startswith(('ret', 'jmp', 'j', 'call')):
                    _append_stack(stores, records, limit)
                    _append_sequence(sequence, records, limit)
                    stores = {}
                    sequence = []
                    since_store = 0
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
                    blocks.append((offset, size, symbol.name))
        if not blocks:
            for section in data_sections.values():
                if section['sh_size'] > MAX_SCAN_BYTES:
                    warnings.append('data byte scan limit reached')
                    continue
                for match in re.finditer(rb'[^\x00]+', section.data()):
                    if not 16 <= len(match.group()) <= 256:
                        continue
                    blocks.append((section['sh_offset'] + match.start(), len(match.group()), None))
                    if len(blocks) >= 128:
                        warnings.append('XOR data block limit reached')
                        break
        seen_blocks = set()
        for offset, length, symbol in blocks[:128]:
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
            encoded = stream.read(length).rstrip(b'\0')
            for candidate in recover_single_byte(encoded, max_candidates=1):
                if candidate['key_hex'] == '00' or candidate['data'] == encoded:
                    continue
                records.append({'kind': 'xor', 'data': candidate['data'],
                                'text': candidate['data'].decode('ascii', 'replace'),
                                'encoding': 'ASCII', 'key_hex': candidate['key_hex'],
                                'source_locator': {'backend': 'symbol-data-xor' if symbol else 'data-run-xor',
                                                   'file_offset': offset, 'length': len(encoded),
                                                   'symbol': symbol}, 'state': 'candidate',
                                'backend': 'single-byte-xor'})
    return records, warnings


def inspect_strings(path: Path, *, max_source_bytes: int = MAX_SOURCE_BYTES,
                    max_records: int = MAX_RECORDS, timeout: float = 20,
                    floss_path: str | None = None) -> tuple[list[dict], list[str]]:
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
    executable = floss_path or shutil.which('floss')
    if executable:
        document, warning = _floss(path.resolve(), executable, deadline)
        if warning:
            warnings.append(warning)
        elif document is not None:
            found, notices = _floss_records(document, max_records)
            records.extend(found)
            warnings.extend(notices)
    else:
        warnings.append('FLOSS backend unavailable; decoded and compiler-specific string coverage incomplete')
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
