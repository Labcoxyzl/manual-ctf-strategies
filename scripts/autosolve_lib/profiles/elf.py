"""Bounded static x86 ELF protections, symbols, and short gadget leads."""

from pathlib import Path


MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_SCAN_BYTES = 1024 * 1024
MAX_SEGMENTS = 128
MAX_SECTIONS = 512
MAX_SYMBOL_SCAN = 4096


def _gadgets(stream, segments, bits: int, limit: int) -> tuple[list[dict], list[str]]:
    names = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi") if bits == 32 else (
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi")
    found = []
    warnings = []
    remaining = MAX_SCAN_BYTES
    executable_bytes = sum(segment["p_filesz"] for segment in segments
                           if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1)
    for index, segment in enumerate(segments):
        if segment["p_type"] != "PT_LOAD" or not segment["p_flags"] & 1:
            continue
        if not segment["p_filesz"]:
            continue
        length = min(segment["p_filesz"], remaining)
        if length <= 0:
            break
        stream.seek(segment["p_offset"])
        code = stream.read(length)
        remaining -= len(code)
        if len(code) != length:
            warnings.append("short executable segment read")
            break
        for offset, byte in enumerate(code):
            if byte != 0xc3:
                continue
            leads = []
            if offset >= 2 and code[offset - 2:offset] == b"\x0f\x05" and bits == 64:
                leads.append((offset - 2, "syscall; ret"))
            if offset >= 1:
                previous = code[offset - 1]
                if 0x58 <= previous <= 0x5f:
                    leads.append((offset - 1, f"pop {names[previous - 0x58]}; ret"))
                elif previous == 0xc9:
                    leads.append((offset - 1, "leave; ret"))
            leads.append((offset, "ret"))
            for start, instruction in leads:
                if len(found) == limit:
                    warnings.append("gadget output limit reached")
                    return found, warnings
                found.append({"instructions": instruction,
                              "bytes": code[start:offset + 1].hex(),
                              "vaddr": segment["p_vaddr"] + start,
                              "file_offset": segment["p_offset"] + start,
                              "segment": index})
    if executable_bytes > MAX_SCAN_BYTES:
        warnings.append("executable segment byte scan limit reached")
    return found, warnings


def inspect_elf(path: Path, *, max_bytes: int = MAX_SOURCE_BYTES,
                max_symbols: int = 64, max_gadgets: int = 64) -> tuple[dict | None, list[str]]:
    """Inspect a local ELF file without executing or resolving runtime addresses."""
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    if max_bytes <= 0 or not 0 < max_symbols <= 256 or not 0 < max_gadgets <= 256:
        raise ValueError("ELF byte and output limits must be positive and bounded")
    path = Path(path)
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None, ["ELF source byte limit reached"]
        if size < 52:
            return None, ["malformed ELF: header is too short"]
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            machine = elf.header["e_machine"]
            if machine not in ("EM_386", "EM_X86_64"):
                return None, [f"unsupported ELF architecture: {machine}"]
            bits = elf.elfclass
            if (machine, bits) not in (("EM_386", 32), ("EM_X86_64", 64)):
                return None, ["unsupported ELF machine/class combination"]
            elf_type = elf.header["e_type"]
            if elf_type not in ("ET_EXEC", "ET_DYN"):
                return None, [f"unsupported ELF type: {elf_type}"]
            if not elf.little_endian:
                return None, ["unsupported x86 ELF endianness"]
            if elf.num_segments() > MAX_SEGMENTS or elf.num_sections() > MAX_SECTIONS:
                return None, ["ELF segment or section count limit reached"]

            segments = list(elf.iter_segments())
            for segment in segments:
                if segment["p_offset"] + segment["p_filesz"] > size:
                    return None, ["malformed ELF: segment exceeds file size"]
            gnu_stack = next((segment for segment in segments
                              if segment["p_type"] == "PT_GNU_STACK"), None)
            relro = any(segment["p_type"] == "PT_GNU_RELRO" for segment in segments)
            bind_now = False
            for segment in segments:
                if segment["p_type"] != "PT_DYNAMIC":
                    continue
                for tag in segment.iter_tags():
                    kind = tag.entry.d_tag
                    if kind == "DT_BIND_NOW" or (kind == "DT_FLAGS" and tag.entry.d_val & 0x8) or (
                            kind == "DT_FLAGS_1" and tag.entry.d_val & 0x1):
                        bind_now = True

            symbols = []
            seen = set()
            canary = False
            scanned = 0
            warnings = []
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                for symbol in section.iter_symbols():
                    scanned += 1
                    if scanned > MAX_SYMBOL_SCAN:
                        warnings.append("symbol scan limit reached")
                        break
                    name = symbol.name
                    if name in ("__stack_chk_fail", "__stack_chk_fail_local"):
                        canary = True
                    if (symbol["st_info"]["type"] != "STT_FUNC" or
                            symbol["st_shndx"] == "SHN_UNDEF" or not symbol["st_value"] or
                            not name or name in seen):
                        continue
                    seen.add(name)
                    if len(symbols) < max_symbols:
                        address = symbol["st_value"]
                        containing = next((segment for segment in segments
                                           if segment["p_type"] == "PT_LOAD" and
                                           segment["p_vaddr"] <= address <
                                           segment["p_vaddr"] + segment["p_filesz"]), None)
                        symbols.append({"name": name[:256], "vaddr": symbol["st_value"],
                                        "file_offset": (containing["p_offset"] + address -
                                                        containing["p_vaddr"])
                                        if containing else None,
                                        "size": symbol["st_size"],
                                        "section": str(symbol["st_shndx"]),
                                        "source_table": section.name})
                if scanned > MAX_SYMBOL_SCAN:
                    break
            if len(seen) > max_symbols:
                warnings.append("symbol output limit reached")
            gadgets, gadget_warnings = _gadgets(stream, segments, bits, max_gadgets)
            warnings.extend(gadget_warnings)
            return {
                "source": str(path.resolve()), "format": "ELF",
                "architecture": "x86-64" if bits == 64 else "x86-32",
                "bits": bits, "endianness": "little" if elf.little_endian else "big",
                "elf_type": elf_type, "entry_vaddr": elf.header["e_entry"],
                "mitigations": {
                    "pie": elf_type == "ET_DYN",
                    "nx": None if gnu_stack is None else not bool(gnu_stack["p_flags"] & 1),
                    "relro": "full" if relro and bind_now else "partial" if relro else "none",
                    "canary": "detected" if canary else "unknown" if scanned > MAX_SYMBOL_SCAN
                    else "not detected",
                },
                "mitigation_evidence": {
                    "pie": "ELF e_type", "nx": "PT_GNU_STACK flags" if gnu_stack else "PT_GNU_STACK absent",
                    "relro": "PT_GNU_RELRO and dynamic bind-now tags",
                    "canary": "__stack_chk_fail symbol presence; absence is not proof every function lacks a canary",
                },
                "symbols": symbols, "gadgets": gadgets,
                "address_note": "Static ELF virtual addresses only; PIE requires a runtime base. "
                                "Gadgets are leads, not proof of exploitability or a working chain.",
            }, warnings
    except (OSError, EOFError, ELFError, ValueError, IndexError, KeyError) as error:
        return None, [f"malformed or unreadable ELF: {type(error).__name__}: {error}"]
