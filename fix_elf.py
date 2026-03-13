#!/usr/bin/env python3
"""
fix_elf.py — scrub DT_VERNEED/DT_VERNEEDNUM/DT_VERSYM from PT_DYNAMIC
and zero the section header table.

Usage:
    python3 fix_elf.py <elf_binary>

Run once after build. Fixes:
    "unsupported version 0 of Verneed record"
"""
import sys, struct, os

if len(sys.argv) < 2:
    print("usage: fix_elf.py <binary>")
    sys.exit(1)

path = sys.argv[1]

with open(path, 'r+b') as f:
    data = bytearray(f.read())

if data[:4] != b'\x7fELF':
    print("Not an ELF file.")
    sys.exit(1)

bits = data[4]

def u16(off): return struct.unpack_from('<H', data, off)[0]
def u32(off): return struct.unpack_from('<I', data, off)[0]
def u64(off): return struct.unpack_from('<Q', data, off)[0]

SCRUB = {0x6ffffff0, 0x6ffffffe, 0x6fffffff, 0x6ffffffc, 0x6ffffffd}

if bits == 2:  # ELF64
    e_phoff     = u64(32)
    e_phentsize = u16(54)
    e_phnum     = u16(56)

    dyn_offset = None
    dyn_filesz = 0
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        if u32(ph) == 2:  # PT_DYNAMIC
            dyn_offset = u64(ph + 8)
            dyn_filesz = u64(ph + 32)
            break

    if dyn_offset is None:
        print("No PT_DYNAMIC segment found.")
    else:
        off = dyn_offset
        end = dyn_offset + dyn_filesz
        while off + 16 <= end and off + 16 <= len(data):
            tag = u64(off)
            if tag == 0:
                break
            if tag in SCRUB:
                struct.pack_into('<Q', data, off,     0)
                struct.pack_into('<Q', data, off + 8, 0)
                print(f"  Zeroed dynamic tag 0x{tag:x} @ file offset 0x{off:x}")
            off += 16

    # Zero section header table
    struct.pack_into('<Q', data, 40, 0)  # e_shoff
    struct.pack_into('<H', data, 60, 0)  # e_shnum
    struct.pack_into('<H', data, 62, 0)  # e_shstrndx

elif bits == 1:  # ELF32
    e_phoff     = u32(28)
    e_phentsize = u16(42)
    e_phnum     = u16(44)

    dyn_offset = None
    dyn_filesz = 0
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        if u32(ph) == 2:
            dyn_offset = u32(ph + 4)
            dyn_filesz = u32(ph + 16)
            break

    if dyn_offset is None:
        print("No PT_DYNAMIC segment found.")
    else:
        off = dyn_offset
        end = dyn_offset + dyn_filesz
        while off + 8 <= end and off + 8 <= len(data):
            tag = u32(off)
            if tag == 0:
                break
            if tag in SCRUB:
                struct.pack_into('<I', data, off,     0)
                struct.pack_into('<I', data, off + 4, 0)
                print(f"  Zeroed dynamic tag 0x{tag:x} @ file offset 0x{off:x}")
            off += 8

    struct.pack_into('<I', data, 32, 0)
    struct.pack_into('<H', data, 48, 0)
    struct.pack_into('<H', data, 50, 0)

else:
    print(f"Unknown ELF class: {bits}")
    sys.exit(1)

with open(path, 'wb') as f:
    f.write(data)

print("ELF hardening complete.")
