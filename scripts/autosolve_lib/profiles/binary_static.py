"""Bounded, read-only ELF/PE structure and located strings."""

import os
import re
import stat
from pathlib import Path

from .elf import inspect_elf


MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_SCAN_BYTES = 8 * 1024 * 1024
MAX_SYMBOL_SCAN = 4096


def _read_source(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            return None, ["binary source must be a regular file"]
        if before.st_size > limit:
            return None, ["binary source byte limit reached"]
        raw = source.read(limit + 1)
        after = os.fstat(source.fileno())
    if len(raw) > limit:
        return None, ["binary source byte limit reached"]
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        return None, ["binary source changed during reading"]
    return raw, []


def _located_strings(raw, sections, max_strings, warnings):
    scanned = raw[:MAX_SCAN_BYTES]
    if len(raw) > len(scanned):
        warnings.append("string scan byte limit reached")
    candidates = {}
    limited = False
    for encoding, expression in (("ascii", rb"[!-~][ -~]{3,}"),
                                 ("utf-16le", rb"(?:[ -~]\x00){4,}")):
        found = []
        for match in re.finditer(expression, scanned):
            offset = match.start()
            section = next((row for row in sections if row["file_offset"] <= offset <
                            row["file_offset"] + row["raw_size"]), None)
            value = match.group()[:512]
            found.append({"value": value.decode(encoding, "replace")[:256],
                          "encoding": encoding, "file_offset": offset,
                          "section": section["name"] if section else None,
                          "static_vaddr": (section["static_vaddr"] + offset - section["file_offset"]
                                           if section and section["static_vaddr"] is not None else None)})
            if len(found) > max_strings:
                limited = True
                break
        candidates[encoding] = found[:max_strings]
    unicode_count = min(len(candidates["utf-16le"]), max_strings // 4)
    selected = candidates["ascii"][:max_strings - unicode_count]
    selected.extend(candidates["utf-16le"][:unicode_count])
    if limited or len(candidates["ascii"]) + len(candidates["utf-16le"]) > len(selected):
        warnings.append("string output limit reached")
    return sorted(selected, key=lambda row: row["file_offset"])


def _elf_structure(path, raw, max_sections, max_imports, warnings):
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    report, notes = inspect_elf(path)
    warnings.extend(note for note in notes if not note.startswith(("gadget ", "executable segment ")))
    if report is None:
        return None
    try:
        with path.open("rb") as source:
            parsed = ELFFile(source)
            if parsed.num_sections() > max_sections:
                warnings.append("ELF section count limit reached")
                return None
            sections = []
            imports = []
            scanned = 0
            report.pop("gadgets", None)
            report["abi"] = str(parsed.header["e_ident"]["EI_OSABI"])
            report["abi_version"] = int(parsed.header["e_ident"]["EI_ABIVERSION"])
            entry = report["entry_vaddr"]
            segment = next((part for part in parsed.iter_segments()
                            if part["p_type"] == "PT_LOAD" and part["p_vaddr"] <= entry <
                            part["p_vaddr"] + part["p_filesz"]), None)
            report["entry_file_offset"] = (segment["p_offset"] + entry - segment["p_vaddr"]
                                           if segment is not None else None)
            for section in parsed.iter_sections():
                offset, size = section["sh_offset"], section["sh_size"]
                if section["sh_type"] != "SHT_NOBITS" and offset + size > len(raw):
                    warnings.append("malformed ELF: section exceeds file size")
                    return None
                sections.append({"name": section.name[:256], "file_offset": offset,
                                 "raw_size": 0 if section["sh_type"] == "SHT_NOBITS" else size,
                                 "static_vaddr": section["sh_addr"] if section["sh_flags"] & 2 else None,
                                 "virtual_size": size, "flags": int(section["sh_flags"])})
                if not isinstance(section, SymbolTableSection) or section["sh_type"] != "SHT_DYNSYM":
                    continue
                for index, symbol in enumerate(section.iter_symbols()):
                    scanned += 1
                    if scanned > MAX_SYMBOL_SCAN:
                        warnings.append("ELF import symbol scan limit reached")
                        break
                    if symbol["st_shndx"] != "SHN_UNDEF" or not symbol.name:
                        continue
                    if len(imports) >= max_imports:
                        warnings.append("ELF import output limit reached")
                        break
                    imports.append({"name": symbol.name[:256], "library": None,
                                    "symbol_table": section.name,
                                    "symbol_index": index,
                                    "symbol_file_offset": section["sh_offset"] +
                                    index * section["sh_entsize"]})
                if scanned > MAX_SYMBOL_SCAN or len(imports) >= max_imports:
                    break
            report["sections"] = sections
            report["imports"] = imports
            report["import_note"] = "Undefined dynamic symbols; library binding and runtime behavior are not established."
            return report
    except (OSError, EOFError, ELFError, ValueError, KeyError, IndexError) as error:
        warnings.append(f"malformed ELF structure: {type(error).__name__}: {error}")
        return None


def _pe_structure(raw, max_sections, max_imports, warnings):
    import pefile

    try:
        pe = pefile.PE(data=raw, fast_load=True)
        machine = pe.FILE_HEADER.Machine
        bits = {0x14c: 32, 0x8664: 64}.get(machine)
        if bits is None:
            warnings.append(f"unsupported PE architecture: 0x{machine:x}")
            return None
        if (bits, pe.OPTIONAL_HEADER.Magic) not in ((32, 0x10b), (64, 0x20b)):
            warnings.append("unsupported PE machine/optional-header combination")
            return None
        if len(pe.sections) > max_sections:
            warnings.append("PE section count limit reached")
            return None
        sections = []
        image_base = pe.OPTIONAL_HEADER.ImageBase
        for section in pe.sections:
            offset, size = section.PointerToRawData, section.SizeOfRawData
            if offset + size > len(raw):
                warnings.append("malformed PE: section exceeds file size")
                return None
            sections.append({"name": section.Name.rstrip(b"\0").decode("ascii", "replace")[:256],
                             "file_offset": offset, "raw_size": size,
                             "static_vaddr": image_base + section.VirtualAddress,
                             "rva": section.VirtualAddress,
                             "virtual_size": section.Misc_VirtualSize,
                             "flags": section.Characteristics})
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        def file_offset(rva):
            try:
                offset = pe.get_offset_from_rva(rva)
                return offset if 0 <= offset < len(raw) else None
            except (pefile.PEFormatError, ValueError):
                return None

        imports = []
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            library = descriptor.dll.decode("ascii", "replace")[:256]
            for symbol in descriptor.imports:
                if len(imports) >= max_imports:
                    warnings.append("PE import output limit reached")
                    break
                name = symbol.name.decode("ascii", "replace")[:256] if symbol.name else None
                imports.append({"name": name, "ordinal": symbol.ordinal,
                                "library": library, "iat_static_vaddr": symbol.address,
                                "iat_rva": symbol.address - image_base,
                                "iat_file_offset": file_offset(symbol.address - image_base)})
            if len(imports) >= max_imports:
                break
        characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
        relocation_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]
        relocations = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[relocation_index].VirtualAddress)
        dynamic_base = bool(characteristics & 0x40)
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        return {"format": "PE", "architecture": "x86-64" if bits == 64 else "x86-32",
                "bits": bits, "endianness": "little", "abi": "Windows PE",
                "subsystem": pe.OPTIONAL_HEADER.Subsystem, "image_base": image_base,
                "entry_rva": entry_rva, "entry_vaddr": image_base + entry_rva,
                "entry_file_offset": file_offset(entry_rva),
                "sections": sections, "imports": imports,
                "mitigations": {"dynamic_base_declared": dynamic_base,
                                "relocations_declared": relocations,
                                "nx_compatible": bool(characteristics & 0x100),
                                "cfg_declared": bool(characteristics & 0x4000)},
                "mitigation_evidence": {"dynamic_base_declared": "OptionalHeader DllCharacteristics",
                                        "relocations_declared": "Base relocation data-directory RVA",
                                        "nx_compatible": "OptionalHeader DllCharacteristics",
                                        "cfg_declared": "OptionalHeader DllCharacteristics"},
                "address_note": "PE addresses are static image-base values; ASLR can change the runtime base. "
                                "Header flags and imports do not prove runtime behavior.",
                "import_note": "Import table names and IAT locations do not prove a call executes."}
    except (pefile.PEFormatError, OSError, ValueError, KeyError, IndexError, AttributeError) as error:
        warnings.append(f"malformed PE: {type(error).__name__}: {error}")
        return None


def inspect_binary(path: Path, *, max_bytes: int = MAX_SOURCE_BYTES,
                   max_sections: int = 128, max_imports: int = 256,
                   max_strings: int = 256) -> tuple[dict | None, list[str]]:
    """Return static executable evidence with exact file locations, without execution."""
    if not 0 < max_bytes <= MAX_SOURCE_BYTES or not 0 < max_sections <= 512 or not (
            0 < max_imports <= 1024 and 0 < max_strings <= 1024):
        raise ValueError("binary inspection limits must be positive and bounded")
    path = Path(path)
    try:
        raw, warnings = _read_source(path, max_bytes)
    except OSError as error:
        return None, [f"binary source unavailable: {type(error).__name__}: {error}"]
    if raw is None:
        return None, warnings
    if raw.startswith(b"\x7fELF"):
        report = _elf_structure(path, raw, max_sections, max_imports, warnings)
    elif raw.startswith(b"MZ"):
        try:
            report = _pe_structure(raw, max_sections, max_imports, warnings)
        except ImportError:
            return None, ["PE parser unavailable: pefile is not installed"]
    else:
        return None, ["unsupported binary format: expected ELF or PE signature"]
    if report is None:
        return None, warnings
    report["source"] = str(path.resolve())
    report["strings"] = _located_strings(raw, report["sections"], max_strings, warnings)
    return report, warnings
