#!/usr/bin/env bash
# build.sh – Hardened cross-platform build for RV v5
# Supports: Linux, macOS, FreeBSD, OpenBSD, NetBSD
# Usage:
#   ./build.sh              # production build
#   ./build.sh --debug      # debug build (full error messages, symbols)
#   ./build.sh --upx        # production + UPX pack (Linux only)
#   ./build.sh --clean      # remove all build artifacts and rebuild

set -euo pipefail

# ── Parse command-line arguments ──────────────────────────────────────
CLEAN=0
DEBUG=0
UPX_PACK=0
BASE_FLAGS=""

for arg in "$@"; do
  case "$arg" in
    --clean) CLEAN=1 ;;
    --debug) DEBUG=1 ;;
    --upx)   UPX_PACK=1 ;;
  esac
done

# ── Handle --clean flag ───────────────────────────────────────────────
if [ "$CLEAN" -eq 1 ]; then
  echo "==> Cleaning build artifacts..."
  rm -rf build build.sh.tmp build.log
  echo "==> Clean complete. Rebuild initialized."
fi

# ── Build output directory ────────────────────────────────────────────
mkdir -p build

# ── Detect OS ─────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

echo "==> RV v5 build  OS=$OS  ARCH=$ARCH  DEBUG=$DEBUG"

# ── Detect compiler ───────────────────────────────────────────────────
if command -v gcc &>/dev/null; then
  CC=gcc
elif command -v clang &>/dev/null; then
  CC=clang
elif command -v cc &>/dev/null; then
  CC=cc
else
  echo "ERROR: no C compiler found" >&2; exit 1
fi

# Ensure current directory is in include path so project-local headers (eg. stub elf.h)
# are found before system headers, particularly on macOS where /usr/include/elf.h
# is absent but some system headers may try to include it.
BASE_FLAGS="$BASE_FLAGS -I."

echo "==> Compiler: $CC"

# ── Detect pkg-config / library paths ────────────────────────────────
PKG_CONFIG=pkg-config
command -v "$PKG_CONFIG" &>/dev/null || PKG_CONFIG=""

get_flags() {
  local lib="$1"
  if [ -n "$PKG_CONFIG" ] && $PKG_CONFIG --exists "$lib" 2>/dev/null; then
    echo "$($PKG_CONFIG --cflags --libs "$lib")"
  else
    # Fallback: common install locations
    case "$lib" in
      libsodium)
        if [[ "$OS" == "Darwin" ]]; then
          if [[ -d "/opt/homebrew/opt/libsodium/include" ]]; then
            echo "-I/opt/homebrew/opt/libsodium/include -L/opt/homebrew/opt/libsodium/lib -lsodium"
          elif [[ -d "/usr/local/opt/libsodium/include" ]]; then
            echo "-I/usr/local/opt/libsodium/include -L/usr/local/opt/libsodium/lib -lsodium"
          else
            echo "Error: libsodium not found. Install with 'brew install libsodium'" >&2
            exit 1
          fi
        else
          echo "-lsodium"
        fi
        ;;
      libcurl) echo "-lcurl" ;;
      libelf)  echo "-lelf" ;;
    esac
  fi
}

SODIUM_FLAGS="$(get_flags libsodium)"
CURL_FLAGS="$(get_flags libcurl)"

# libelf only needed on Linux (for self-integrity ELF section parsing)
ELF_FLAGS=""
if [ "$OS" = "Linux" ]; then
  ELF_FLAGS="$(get_flags libelf)"
fi

echo "==> libsodium: $SODIUM_FLAGS"
echo "==> libcurl:   $CURL_FLAGS"
[ -n "$ELF_FLAGS" ] && echo "==> libelf:    $ELF_FLAGS"

# ── Base compiler flags ───────────────────────────────────────────────
BASE_FLAGS="-O2 -std=c11 -Wall -Wextra -Wno-unused-parameter"
BASE_FLAGS="$BASE_FLAGS -fstack-protector-strong"
BASE_FLAGS="$BASE_FLAGS -fvisibility=hidden"
BASE_FLAGS="$BASE_FLAGS -DSTRKEY=0xA7"

# _FORTIFY_SOURCE (Linux + glibc; not all BSDs support it)
if [ "$OS" = "Linux" ]; then
  BASE_FLAGS="$BASE_FLAGS -D_FORTIFY_SOURCE=2"
fi

# Position-independent executable
BASE_FLAGS="$BASE_FLAGS -fPIE"

# PIE link flag differs by toolchain
case "$OS" in
  Linux|FreeBSD|OpenBSD|NetBSD)
    PIE_LINK="-pie" ;;
  Darwin)
    PIE_LINK="" ;;  # clang on macOS enables PIE by default
  *)
    PIE_LINK="-pie" ;;
esac

# Stack clash protection (GCC 7+ and clang 11+; skip if unsupported)
if $CC -fstack-clash-protection -x c /dev/null -o /dev/null 2>/dev/null; then
  BASE_FLAGS="$BASE_FLAGS -fstack-clash-protection"
fi

# Control-flow enforcement (Intel CET, x86-64 only, GCC/clang)
if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then
  if $CC -fcf-protection=full -x c /dev/null -o /dev/null 2>/dev/null; then
    BASE_FLAGS="$BASE_FLAGS -fcf-protection=full"
  fi
fi

# Strip unwind tables (reduces metadata leakage)
if $CC -fno-unwind-tables -fno-asynchronous-unwind-tables -x c /dev/null -o /dev/null 2>/dev/null; then
  BASE_FLAGS="$BASE_FLAGS -fno-unwind-tables -fno-asynchronous-unwind-tables"
fi

# ── Linker hardening ──────────────────────────────────────────────────
LFLAGS="$PIE_LINK"

case "$OS" in
  Linux)
    # Full RELRO, immediate binding, no-exec stack, gc-sections
    if $CC -Wl,-z,relro,-z,now -x c /dev/null -o /dev/null 2>/dev/null; then
      LFLAGS="$LFLAGS -Wl,-z,relro,-z,now"
    fi
    LFLAGS="$LFLAGS -Wl,-z,noexecstack -Wl,--gc-sections"
    ;;
  Darwin)
    LFLAGS="$LFLAGS -Wl,-dead_strip"
    ;;
  FreeBSD|OpenBSD|NetBSD)
    if $CC -Wl,-z,relro,-z,now -x c /dev/null -o /dev/null 2>/dev/null; then
      LFLAGS="$LFLAGS -Wl,-z,relro,-z,now"
    fi
    ;;
esac

# ── Debug vs production flags ─────────────────────────────────────────
if [ "$DEBUG" -eq 1 ]; then
  BUILD_FLAGS="$BASE_FLAGS -g -DRV_DEBUG"
  OUT="build/rv_debug"
  echo "==> DEBUG build → $OUT"
else
  BUILD_FLAGS="$BASE_FLAGS"
  OUT="build/rv"
  echo "==> PRODUCTION build → $OUT"
fi

# ── Compile ───────────────────────────────────────────────────────────
echo "==> Compiling rv.c..."
$CC $BUILD_FLAGS \
    -o "$OUT" rv.c \
    $LFLAGS \
    $SODIUM_FLAGS \
    $CURL_FLAGS \
    $ELF_FLAGS \
    -lm

echo "==> Compiled: $OUT"

# Run fix_elf.py on Linux to scrub DT_VERNEED tags (fixes Verneed version 0 error)
if [ "$OS" = "Linux" ] && [ "$DEBUG" -eq 0 ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ -f "$SCRIPT_DIR/fix_elf.py" ]; then
    echo "==> Running fix_elf.py..."
    python3 "$SCRIPT_DIR/fix_elf.py" "$OUT"
  else
    echo "  (fix_elf.py not found next to build.sh — skipping ELF version scrub)"
  fi
fi

# ── Production hardening steps ───────────────────────────────────────
if [ "$DEBUG" -eq 0 ]; then

  # Strip
  echo "==> Stripping..."
  case "$OS" in
    Darwin)
      strip "$OUT"
      ;;
    *)
      STRIP_FLAGS="--strip-all"
      # Remove metadata sections (GNU strip only)
      for sec in .comment .note .note.ABI-tag .note.gnu.build-id \
                 .gnu.version .gnu.version_r; do
        if strip --remove-section="$sec" "$OUT" 2>/dev/null; then true; fi
      done
      strip $STRIP_FLAGS "$OUT" 2>/dev/null || strip "$OUT"
      ;;
  esac

  # Remove section header table + scrub version-info dynamic tags on ELF.
  #
  # WHY: Zeroing e_shoff/e_shnum/e_shstrndx hides sections from objdump/readelf,
  # but ld.so resolves DT_VERNEED via the *program headers* (PT_DYNAMIC), not the
  # section headers.  If .gnu.version_r bytes remain in the file while the section
  # header is gone, ld.so reads a Verneed record with vn_version=0 and aborts:
  #   "unsupported version 0 of Verneed record"
  # Fix: zero DT_VERNEED + DT_VERNEEDNUM in PT_DYNAMIC so ld.so never looks for
  # them, then zero the section header table as before.
  if [ "$OS" != "Darwin" ]; then
    echo "==> Scrubbing ELF version info + section header table..."
    python3 - "$OUT" <<'PYEOF'
import sys, struct

path = sys.argv[1]
with open(path, 'r+b') as f:
    magic = f.read(4)
    if magic != b'\x7fELF':
        print("  (not ELF, skipping)")
        sys.exit(0)
    f.seek(0)
    data = bytearray(f.read())

bits = data[4]  # 1=ELF32, 2=ELF64

def u16(off): return struct.unpack_from('<H', data, off)[0]
def u32(off): return struct.unpack_from('<I', data, off)[0]
def u64(off): return struct.unpack_from('<Q', data, off)[0]

if bits == 2:  # ELF64
    e_phoff  = u64(32)
    e_phentsize = u16(54)
    e_phnum  = u16(56)

    # Walk PT_DYNAMIC (type=2) program header to find the dynamic segment offset
    PT_DYNAMIC = 2
    dyn_offset = None
    dyn_filesz = 0
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        if u32(ph) == PT_DYNAMIC:
            dyn_offset = u64(ph + 8)   # p_offset
            dyn_filesz = u64(ph + 32)  # p_filesz
            break

    # Each Elf64_Dyn entry is 16 bytes: d_tag(8) + d_val/d_ptr(8)
    DT_VERSYM      = 0x6ffffff0
    DT_VERNEED     = 0x6ffffffe
    DT_VERNEEDNUM  = 0x6fffffff
    DT_VERDEF      = 0x6ffffffc
    DT_VERDEFNUM   = 0x6ffffffd
    SCRUB_TAGS = {DT_VERSYM, DT_VERNEED, DT_VERNEEDNUM, DT_VERDEF, DT_VERDEFNUM}

    if dyn_offset is not None:
        off = dyn_offset
        end = dyn_offset + dyn_filesz
        while off + 16 <= end and off + 16 <= len(data):
            tag = u64(off)
            if tag == 0:  # DT_NULL
                break
            if tag in SCRUB_TAGS:
                struct.pack_into('<Q', data, off,     0)  # tag  → DT_NULL(0)
                struct.pack_into('<Q', data, off + 8, 0)  # value → 0
                print(f"  Zeroed dynamic tag 0x{tag:x} @ file offset 0x{off:x}")
            off += 16

    # Zero section header table fields in ELF header
    struct.pack_into('<Q', data, 40, 0)   # e_shoff     = 0
    struct.pack_into('<H', data, 60, 0)   # e_shnum     = 0
    struct.pack_into('<H', data, 62, 0)   # e_shstrndx  = 0

elif bits == 1:  # ELF32
    e_phoff     = u32(28)
    e_phentsize = u16(42)
    e_phnum     = u16(44)

    PT_DYNAMIC = 2
    dyn_offset = None
    dyn_filesz = 0
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        if u32(ph) == PT_DYNAMIC:
            dyn_offset = u32(ph + 4)   # p_offset
            dyn_filesz = u32(ph + 16)  # p_filesz
            break

    DT_VERSYM     = 0x6ffffff0
    DT_VERNEED    = 0x6ffffffe
    DT_VERNEEDNUM = 0x6fffffff
    DT_VERDEF     = 0x6ffffffc
    DT_VERDEFNUM  = 0x6ffffffd
    SCRUB_TAGS = {DT_VERSYM, DT_VERNEED, DT_VERNEEDNUM, DT_VERDEF, DT_VERDEFNUM}

    if dyn_offset is not None:
        off = dyn_offset
        end = dyn_offset + dyn_filesz
        while off + 8 <= end and off + 8 <= len(data):
            tag = u32(off)
            if tag == 0:
                break
            if tag in SCRUB_TAGS:
                struct.pack_into('<I', data, off,     0)
                struct.pack_into('<I', data, off + 4, 0)
                print(f"  Zeroed dynamic tag 0x{tag:x} @ file offset 0x{off:x}")
            off += 8

    struct.pack_into('<I', data, 32, 0)   # e_shoff
    struct.pack_into('<H', data, 48, 0)   # e_shnum
    struct.pack_into('<H', data, 50, 0)   # e_shstrndx

with open(path, 'wb') as f:
    f.write(data)
print("  ELF hardening complete.")
PYEOF
  fi

  # Inject self-integrity hash (ELF only; skipped on macOS Mach-O)
  if [ "$OS" != "Darwin" ] && command -v python3 &>/dev/null; then
    if python3 -c "import pyelftools" 2>/dev/null; then
      echo "==> Injecting self-integrity hash..."
      python3 inject_hash.py "$OUT" && echo "  Hash injected."
    else
      echo "  (pyelftools not found — skipping hash injection)"
      echo "  Install with: pip3 install pyelftools"
    fi
  fi

  # UPX (Linux only, optional)
  if [ "$UPX_PACK" -eq 1 ]; then
    if [ "$OS" = "Linux" ] && command -v upx &>/dev/null; then
      echo "==> UPX packing..."
      upx --best --overlay=strip "$OUT" && echo "  Packed."
    else
      echo "  (UPX not available or not on Linux, skipping)"
    fi
  fi

  echo ""
  echo "==> Build complete: $OUT"
  ls -lh "$OUT"
fi
