# RV3

**Build: v6 | Crypto: ML-KEM-1024 + SHAKE-256 + AES-256-GCM + Argon2id**

RV encrypts folders and files into a portable `.otc` container. The container is unreadable without both the `.key` file and the master password. The cryptographic design is hybrid classical + post-quantum, meaning it is secure against both today's attacks and future quantum computers.

---

## How It Works

### Output files

Every encode operation produces two files:

| File | Purpose |
|---|---|
| `<name>_root.otc` | The encrypted container — contains all your files |
| `<name>.key` | The encrypted key file — stores all per-file passwords, protected by your master password |

You need **both** files plus the master password to decode. Losing either file means permanent data loss.

---

## Cryptographic Stack

| Layer | Algorithm | Role |
|---|---|---|
| Key encapsulation | ML-KEM-1024 (FIPS 203) | Post-quantum key exchange |
| File encryption | XChaCha20-Poly1305 | Per-file authenticated encryption |
| Container frame | AES-256-GCM | Outer container encryption |
| Key derivation | Argon2id (auto-tuned) + SHAKE-256 | Password → key, memory-hard |
| Hybrid KDF | SHAKE-256(Argon2id \|\| ML-KEM-SS) | 256-bit post-quantum security |
| Hashing / MAC | SHAKE-256 / SHA3-512 | Integrity, path encryption, tree hash |
| Compression | LZ4 (built-in, no dependency) | Applied before encryption |

The Argon2id parameters are **auto-tuned at runtime** — RV reads `/proc/meminfo` and uses up to 1/4 of available RAM, clamped between INTERACTIVE and SENSITIVE presets.

---

## Container Architecture

### Structure

Files are grouped in batches of 3 into **sub-containers**. Each sub-container is independently encrypted. Sub-containers are then bundled into a root archive which is encrypted again with a separate root password.

```
<name>_root.otc
└── root archive (XChaCha20-Poly1305, root password)
    ├── sub-container 1 (XChaCha20-Poly1305, random 30-char password)
    │   ├── file A  (XChaCha20-Poly1305, random 30-char password)
    │   ├── file B
    │   └── file C
    ├── sub-container 2
    │   └── ...
    └── ...
```

Every layer uses a **separate randomly generated 30-character Base62 password**. Compromising one file's password reveals nothing about any other file.

### v6 Container features

- **Encrypted file paths** — filenames inside the container are encrypted with a path-key derived from the container password; an attacker with the `.otc` file cannot see the names of files inside
- **Tree hash** — a SHAKE-256 hash of all file contents is computed during encode and verified during decode; tampering with any file is detected before anything is written to disk
- **Container index** — each sub-container has an encrypted index enabling random-access partial decodes
- **LZ4 compression** — all data is compressed before encryption; incompressible data is stored raw automatically

### `.key` file format (v2)

```
"RVKF\x02" (5 bytes)   magic + version
entry_count (4 bytes LE)
salt (SALT_LEN bytes)
nonce (OTC_NONCE_LEN bytes)
ciphertext + tag        encrypted key entries (label:password\n per line)
outer_mac (32 bytes)    SHAKE-256-MAC over all preceding bytes
```

The outer MAC detects truncation or bit-flips before AEAD decryption is attempted. The entry count in the plaintext header catches truncated key files immediately.

---

## Building

### Dependencies

| Library | Purpose |
|---|---|
| libsodium | AES-256-GCM, XChaCha20-Poly1305, Argon2id, SHA-256 |
| libcurl | Public IP fetch (US enforcement check) |
| libpthread | Parallel encode workers |
| libm | `log()` for password entropy estimation |
| libelf | Linux only — self-integrity ELF section parsing |

All post-quantum crypto (ML-KEM-1024 / Kyber), SHAKE-256, SHA3-512, and LZ4 are implemented directly in `rv.c` with no external dependency.

### Install dependencies

**Debian / Ubuntu**
```bash
sudo apt install build-essential libsodium-dev libcurl4-openssl-dev libelf-dev
```

**Arch Linux**
```bash
sudo pacman -S base-devel libsodium curl elfutils
```

**macOS (Homebrew)**
```bash
brew install libsodium curl
```

**Python (optional — for hash injection)**
```bash
pip3 install pyelftools
```

### Compile

```bash
git clone https://github.com/ManyHost/RV3.git
cd RV3
chmod +x build.sh
./build.sh
```

Binary is placed at `build/rv`.

**Build options:**
```bash
./build.sh           # production (optimised, stripped, hardened)
./build.sh --debug   # debug build with symbols
./build.sh --upx     # production + UPX pack (Linux only)
./build.sh --clean   # clean artifacts then rebuild
```

The production build automatically:
- Strips all symbols and debug info
- Removes `.comment`, `.note`, `.gnu.version*` ELF sections
- Zeroes `DT_VERNEED` / `DT_VERNEEDNUM` dynamic tags (prevents `ld.so` version errors)
- Enables full RELRO, immediate binding, non-executable stack, PIE, stack clash protection, CET (where supported)
- Optionally injects a SHA-256 self-integrity hash into `.rodata` (`inject_hash.py`)

---

## Usage

```
./rv encode  <folder|file> [-r] [-i] [--dry-run] [--weak-pw] [--decoy <src>] [--stdin-pw]
./rv decode  <name_root.otc> <name.key> [-i] [--stdin-pw]
./rv list    <name_root.otc> <name.key>
./rv rekey   <name.key>
./rv inspect <name_root.otc> <name.key>
./rv extract <name_root.otc> <name.key> <relpath>
./rv split   <name_root.otc> <N>
./rv join    <name_root.otc.001> <out.otc>
./rv run     <file>
```

---

## Commands

### `encode`

Encrypts a folder or single file into a `.otc` + `.key` pair.

```bash
./rv encode /home/user/documents
# → documents_root.otc
# → documents.key
# → documents_root.snap  (delta snapshot for incremental re-encodes)
```

- Prompts for a master password (minimum 40-bit entropy enforced by default)
- Files are split into groups of 3, each group encrypted as a sub-container in parallel across all CPU cores
- Delta encoding: on re-encode, only changed files (detected via SHAKE-256 content hash) are re-encrypted
- Checkpoint/resume: if interrupted, the next run skips already-completed containers (`.ckpt` file)
- Compresses with LZ4 before encrypting; prints compression ratio on completion

**Flags:**

| Flag | Effect |
|---|---|
| `-r` | Securely delete source files after successful encode (3-pass overwrite: random → zero → random, then unlink) |
| `-i` | Ignore RAM/swap safety check (use with caution — key material may spill to swap) |
| `--dry-run` | Show what would be created without writing anything |
| `--weak-pw` | Allow master passwords below 40-bit entropy |
| `--decoy <src>` | Embed a decoy archive (see Plausible Deniability below) |
| `--stdin-pw` | Read master password from stdin instead of `/dev/tty` |

### `decode`

Decrypts a container back to the original folder structure.

```bash
./rv decode documents_root.otc documents.key
# → documents/ folder restored
```

- Verifies the tree hash of every sub-container before writing any file to disk
- Runs decode workers in parallel across all CPU cores
- After 5 consecutive wrong password attempts the container **destroys itself** (overwritten with random bytes, then deleted)
- Checks for the `.ok` sentinel file and warns if it is absent (indicates an interrupted encode)

**Flags:** `-i`, `--stdin-pw` (same as encode)

### `list`

Shows every file inside the container with its plaintext and encrypted sizes, without extracting anything.

```bash
./rv list documents_root.otc documents.key
```

### `inspect`

Shows container-level metadata: number of sub-containers, total encrypted size, files per container.

```bash
./rv inspect documents_root.otc documents.key
```

### `extract`

Decrypts and writes a single file by its relative path, without decoding the entire container.

```bash
./rv extract documents_root.otc documents.key reports/q4.pdf
# → q4.pdf written to current directory
```

### `rekey`

Changes the master password on the `.key` file without touching the `.otc` container at all. The sub-container passwords are not re-generated — only the outer encryption of the key file changes.

```bash
./rv rekey documents.key
```

### `split` / `join`

Splits a container into N equal shards for distributed storage. Each shard has a self-describing header with total size, shard count and index. Shards can be recombined in any order.

```bash
./rv split documents_root.otc 3
# → documents_root.otc.001
# → documents_root.otc.002
# → documents_root.otc.003

./rv join documents_root.otc.001 restored.otc
```

### `run`

Decrypts a file and executes it entirely in memory. On Linux this uses `memfd_create` + `fexecve` — the decrypted binary never appears on the filesystem. On other POSIX systems a secure temp file is used, overwritten and unlinked immediately after execution.

```bash
./rv run encrypted_binary
```

---

## Security Features

### Plausible deniability (`--decoy`)

```bash
./rv encode /home/user/real_files --decoy /home/user/fake_files
```

The `.otc` file contains two independent archives: a real one and a decoy. The `.key` file stores both a `root` password (real data) and a `decoy_root` password (fake data). Under coercion, you can hand over a key file that only contains the `decoy_root` entry — the adversary decrypts and sees only the fake files. The real data is indistinguishable from random bytes without the real key.

### Anti-tamper / anti-analysis

- **Anti-debug** — Checks `ptrace(PTRACE_TRACEME)` and `/proc/self/status TracerPid`, and scans the parent process name against a list of known debuggers (gdb, lldb, strace, ltrace, radare2, frida, valgrind). Exits immediately if detected.
- **VM detection** — Checks CPUID hypervisor bit, known hypervisor vendor strings, and DMI strings for QEMU, KVM, VirtualBox, VMware, Xen, and cloud providers. The `run` command refuses to execute in a VM.
- **Self-integrity check** — If `inject_hash.py` has been run after the build, the binary verifies a SHA-256 hash of its own `.text` section at startup. A patched binary exits immediately.
- **Junk instruction traps** — `ANTIDIS_TRAP()` injects invalid byte sequences that crash linear-sweep disassemblers.
- **Dead code noise** — `FAKE_CRYPTO_NOISE()` executes real AES-256-GCM operations on random data to confuse timing analysis.
- **Stack canaries** — `STACK_CANARY_INIT/SAVE/CHECK` macros place random values on the stack around sensitive functions and verify them on return.
- **Signal wipe handler** — SIGINT and SIGTERM zero all registered sensitive memory regions before exit, preventing key material from remaining in RAM.

### Brute-force protection

After **5 consecutive failed decode attempts** on the same container, RV overwrites the `.otc` file with random bytes and unlinks it. The counter resets on any successful decode.

### RAM / swap safety

At startup and at key points during encode/decode, RV reads `/proc/meminfo` and aborts if the system is actively using swap. Key material in swap is a serious security risk. Override with `-i` only if you understand the implications.

### Password strength

The master password is evaluated for entropy using character-class diversity, length, repeated-character penalty, and keyboard-walk penalty. Passwords below 40 bits are rejected by default (`--weak-pw` overrides). The strength and a tip are printed for every encode.

---

## Performance

Encoding is parallelised across all available CPU cores. Each sub-container is encrypted by an independent worker thread; the number of concurrent workers is `CPU_count × 2`. A live progress bar shows throughput (MiB/s), ETA, bytes done/total, and elapsed time, updated every 100 ms by a background ticker thread.

Decoding is similarly parallelised at the sub-container level.

**RAM requirement:** the root archive must fit in RAM during encode and decode. For very large datasets ensure you have sufficient free memory. The swap safety check will abort before causing a system slowdown.

---

## Legacy mode (`--mode rv2`)

RV includes a legacy RV2 mode for backward compatibility with older containers using AES-256-GCM + Argon2id (no post-quantum layer).

```bash
./rv --mode rv2 encode <file|folder> <password> [backup]
./rv --mode rv2 decode <file|folder.rv2> <password>
./rv --mode rv2 run    <file> <password>
```

---

## Important Notes

- **Keep your `.key` file separate from your `.otc` file.** Storing both together removes a layer of security. Ideally keep the `.key` on a different device or location.
- **There is no password recovery.** If you lose the master password or the `.key` file the data is permanently unrecoverable.
- **The `-r` flag is irreversible.** Source files are overwritten three times and deleted. Test in an isolated directory first.
- **Delta snapshots** (`.snap` files) are stored next to the output. They are not sensitive but are needed for efficient incremental re-encodes.
- **Checkpoints** (`.ckpt` files) are automatically deleted on successful encode completion. If a `.ckpt` remains, the next encode run will resume from where it stopped.

---

## Dependencies Summary

| Dependency | Version | Required |
|---|---|---|
| libsodium | ≥ 1.0.18 | Yes |
| libcurl | ≥ 7.85.0 | Yes |
| libpthread | POSIX | Yes |
| libm | POSIX | Yes |
| libelf | Any | Linux only |
| gcc or clang | gcc ≥ 7 / clang ≥ 11 | Build only |
| python3 + pyelftools | Any | Optional (hash injection) |

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
