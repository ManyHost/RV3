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
if [ "$ARCH" = "x86_64"] || [ "$ARCH" = "amd64" ]; then
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
    $ELF_FLAGS

echo "==> Compiled: $OUT"

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

  # Remove section header table on ELF (makes section-based analysis harder)
  if [ "$OS" != "Darwin" ]; then
    echo "==> Removing ELF section header table..."
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

# ELF64 header offsets:
#   e_shoff     @ 40, 8 bytes
#   e_shnum     @ 60, 2 bytes
#   e_shstrndx  @ 62, 2 bytes
if data[4] == 2:  # ELF64
    struct.pack_into('<Q', data, 40, 0)   # e_shoff  = 0
    struct.pack_into('<H', data, 60, 0)   # e_shnum  = 0
    struct.pack_into('<H', data, 62, 0)   # e_shstrndx = 0
elif data[4] == 1:  # ELF32
    struct.pack_into('<I', data, 32, 0)   # e_shoff
    struct.pack_into('<H', data, 48, 0)   # e_shnum
    struct.pack_into('<H', data, 50, 0)   # e_shstrndx

with open(path, 'wb') as f:
    f.write(data)
print("  Section header table zeroed.")
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