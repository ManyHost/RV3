#!/usr/bin/env python3
"""
inject_hash.py – Post-link self-integrity hash injector for RV v5

Supported formats:
  ELF (Linux, FreeBSD, OpenBSD, NetBSD) — full support
  Mach-O (macOS) — skipped (prints notice)

Usage:
  python3 inject_hash.py <binary>

What it does:
  1. Finds the .text section of the binary.
  2. SHA-256 hashes it.
  3. Locates the __rv_text_hash symbol in the symbol table.
  4. Writes the 32-byte hash into the binary at that symbol's file offset.
  5. Verifies that the .text section is unchanged (hash symbol must be
     in .rodata, not .text — this is enforced by the section attribute
     in rv.c).

Requires: pip3 install pyelftools
"""

import sys
import hashlib
import struct
import os

def inject_elf(path):
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError:
        print("ERROR: pyelftools not installed. Run: pip3 install pyelftools")
        sys.exit(1)

    with open(path, 'rb') as f:
        elf = ELFFile(f)

        # Find .text section
        text_sec = elf.get_section_by_name('.text')
        if not text_sec:
            print("ERROR: .text section not found")
            sys.exit(1)

        text_data   = text_sec.data()
        text_offset = text_sec['sh_offset']
        text_size   = text_sec['sh_size']
        print(f"  .text  @ offset 0x{text_offset:x}, size {text_size} bytes")

        # SHA-256 hash of .text
        h = hashlib.sha256(text_data).digest()
        print(f"  SHA-256 of .text: {h.hex()}")

        # Find __rv_text_hash symbol
        sym_offset = None
        sym_section = None
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                if sym.name == '__rv_text_hash':
                    sym_offset  = sym['st_value']   # virtual address
                    sym_section_idx = sym['st_shndx']
                    # Resolve VA → file offset
                    # Find the section containing this symbol
                    for i, s in enumerate(elf.iter_sections()):
                        sh_addr  = s['sh_addr']
                        sh_size  = s['sh_size']
                        sh_off   = s['sh_offset']
                        if sh_addr <= sym_offset < sh_addr + sh_size:
                            file_offset = sh_off + (sym_offset - sh_addr)
                            sym_section = s.name
                            break
                    break
            if sym_offset is not None:
                break

        if sym_offset is None:
            print("ERROR: __rv_text_hash symbol not found in binary.")
            print("       Make sure the binary was compiled without --gc-sections")
            print("       removing the symbol, and that it was not stripped.")
            sys.exit(1)

        print(f"  __rv_text_hash VA=0x{sym_offset:x}, section={sym_section}, file_offset=0x{file_offset:x}")

        # Safety check: symbol must NOT be in .text
        if sym_section == '.text':
            print("ERROR: __rv_text_hash is in .text — it must be in .rodata.")
            print("       Check the __attribute__((section(\".rodata\"))) in rv.c.")
            sys.exit(1)

    # Write hash into binary
    with open(path, 'r+b') as f:
        f.seek(file_offset)
        existing = f.read(32)
        if existing != b'\x00' * 32:
            print(f"  WARNING: Existing value at symbol is non-zero: {existing.hex()}")
            print(f"  Overwriting anyway.")
        f.seek(file_offset)
        f.write(h)

    print(f"  Hash written successfully to {path}")

    # Verify: re-read binary and confirm .text hash still matches
    with open(path, 'rb') as f:
        elf2 = ELFFile(f)
        text2 = elf2.get_section_by_name('.text')
        h2 = hashlib.sha256(text2.data()).digest()
        if h2 != h:
            print("ERROR: .text changed after hash injection! Symbol was in .text.")
            sys.exit(1)

    print(f"  Verification passed: .text unchanged after injection.")


def inject_macho(path):
    print(f"  Mach-O binary detected ({path}).")
    print(f"  Self-integrity hash injection is not supported on macOS Mach-O.")
    print(f"  The binary will function without it; the integrity check is a no-op on macOS.")
    print(f"  To add Mach-O support: parse __TEXT,__text and inject into __DATA,__const.")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"ERROR: {path} not found")
        sys.exit(1)

    with open(path, 'rb') as f:
        magic = f.read(4)

    if magic == b'\x7fELF':
        print(f"==> ELF binary: {path}")
        inject_elf(path)
    elif magic[:2] == b'\xfe\xed' or magic[:2] == b'\xce\xfa' or \
         magic[:2] == b'\xcf\xfa' or magic == b'\xca\xfe\xba\xbe':
        print(f"==> Mach-O binary: {path}")
        inject_macho(path)
    else:
        print(f"ERROR: Unrecognised binary format (magic: {magic.hex()})")
        sys.exit(1)


if __name__ == '__main__':
    main()
