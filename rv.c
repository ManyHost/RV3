/*
 * RV v5 – Quantum-Resistant Encrypted Container
 * COPYRIGHT MANYHOST — Quantum-Resistant Encryption Protocol
 * Copyright (c) Manyhost.org 2026
 *
 * Universal POSIX build — Linux, macOS, FreeBSD, OpenBSD, NetBSD.
 * Single source file, no separate headers needed.
 *
 * Build:
 *   gcc -O2 -fstack-protector-strong -fPIE -pie -fvisibility=hidden \
 *       -DSTRKEY=0xA7 -o rv rv.c -lsodium -lcurl -lpthread
 *   strip rv && python3 inject_hash.py rv   # optional: inject .text hash
 *
 * Dependencies: libsodium, libcurl, pthreads   (libelf NOT required)
 *
 * Quantum resistance:
 *   ML-KEM-1024 (FIPS 203)  — replaces all classical KEMs
 *   SHAKE-256 / SHA3-512    — replaces SHA-256 / HMAC-SHA256
 *   Hybrid KDF: SHAKE256(Argon2id || ML-KEM-SS) → 256-bit PQ security
 *
 * Hardware binding (run_secure path only):
 *   HWID = SHA3-512(cpu_id + DMI serials + MAC + public_IP + user_secret)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sched.h>
#include <time.h>
#include <pthread.h>
/* ptrace: available on Linux/macOS/BSD but not all POSIX */
#if defined(__linux__) || defined(__APPLE__) || \
    defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
# include <sys/ptrace.h>
#endif
/* cpuid.h is GCC x86-only */
#if defined(__x86_64__) || defined(__i386__)
# include <cpuid.h>
#endif
/* elf.h removed — minimal ELF types inlined below for portability */
#include <sodium.h>
#include <curl/curl.h>
#include <limits.h>
#include <math.h>

/* ================================================================== */
/* Constants                                                            */
/* ================================================================== */
#define RV2_MAGIC       "RV2C"
#define RV2_MAGIC_LEN   4
#define RV2_VERSION     ((uint8_t)2)
#define RV2_SALT_LEN    16
#define RV2_NONCE_LEN   crypto_aead_aes256gcm_NPUBBYTES
#define RV2_KEY_LEN     crypto_aead_aes256gcm_KEYBYTES
#define RV2_TAG_LEN     crypto_aead_aes256gcm_ABYTES
#define RV2_MAX_PATH    4096
#define RV2_HDR_MIN     (RV2_MAGIC_LEN + 1 + 8 + RV2_SALT_LEN + RV2_NONCE_LEN + RV2_TAG_LEN)

/* ================================================================== */
/* Fatal error                                                          */
/* ================================================================== */
__attribute__((noreturn))
static void rv2_die(const char *msg){
    dprintf(STDERR_FILENO, "rv2: error: %s\n", msg);
    _exit(1);
}

/* ================================================================== */
/* File I/O                                                             */
/* ================================================================== */
static uint8_t *rv2_rfile(const char *path, size_t *sz){
    struct stat st;
    if(stat(path, &st) != 0){
        dprintf(STDERR_FILENO, "rv2: cannot stat: %s (%s)\n", path, strerror(errno));
        rv2_die("stat");
    }
    if(st.st_size < 0 || (uint64_t)st.st_size > 4ULL*1024*1024*1024)
        rv2_die("file too large");
    *sz = (size_t)st.st_size;
    FILE *f = fopen(path, "rb");
    if(!f){ dprintf(STDERR_FILENO, "rv2: open: %s\n", strerror(errno)); rv2_die("open"); }
    uint8_t *buf = malloc(*sz + 1);
    if(!buf){ fclose(f); rv2_die("malloc"); }
    if(*sz > 0 && fread(buf, 1, *sz, f) != *sz){ fclose(f); free(buf); rv2_die("read"); }
    fclose(f);
    return buf;
}

static void rv2_wfile(const char *path, const uint8_t *data, size_t sz){
    char tmp[RV2_MAX_PATH];
    if(snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) rv2_die("path too long");
    FILE *f = fopen(tmp, "wb");
    if(!f) rv2_die("open for write");
    size_t done = 0;
    while(done < sz){
        size_t r = fwrite(data + done, 1, sz - done, f);
        if(!r){ fclose(f); unlink(tmp); rv2_die("write"); }
        done += r;
    }
    fclose(f);
    if(rename(tmp, path) != 0){ unlink(tmp); rv2_die("rename"); }
}

/* ================================================================== */
/* Key derivation – Argon2id moderate                                   */
/* ================================================================== */
static void rv2_derive_key(uint8_t key[RV2_KEY_LEN],
                            const char *pw,
                            const uint8_t salt[RV2_SALT_LEN])
{
    if(crypto_pwhash(key, RV2_KEY_LEN,
                     pw, strlen(pw), salt,
                     crypto_pwhash_OPSLIMIT_MODERATE,
                     crypto_pwhash_MEMLIMIT_MODERATE,
                     crypto_pwhash_ALG_ARGON2ID13) != 0)
        rv2_die("key derivation failed");
}

/* ================================================================== */
/* Encrypt buffer → RV2C blob (heap-allocated, caller frees)           */
/* ================================================================== */
static uint8_t *rv2_encrypt_buf(const uint8_t *in, size_t il,
                                 const char *pw, size_t *out_sz)
{
    uint8_t salt[RV2_SALT_LEN], nonce[RV2_NONCE_LEN], key[RV2_KEY_LEN];
    randombytes_buf(salt,  RV2_SALT_LEN);
    randombytes_buf(nonce, RV2_NONCE_LEN);
    rv2_derive_key(key, pw, salt);

    size_t ct_max = il + RV2_TAG_LEN;
    uint8_t *ct = malloc(ct_max);
    if(!ct){ sodium_memzero(key, RV2_KEY_LEN); rv2_die("malloc ct"); }
    unsigned long long cl;
    if(crypto_aead_aes256gcm_encrypt(ct, &cl, in, il,
                                     NULL, 0, NULL, nonce, key) != 0){
        sodium_memzero(key, RV2_KEY_LEN); free(ct); rv2_die("encrypt");
    }
    sodium_memzero(key, RV2_KEY_LEN);

    /* layout: magic(4) + version(1) + orig_size(8) + salt(16) + nonce(12) + ct */
    size_t total = RV2_MAGIC_LEN + 1 + 8 + RV2_SALT_LEN + RV2_NONCE_LEN + (size_t)cl;
    uint8_t *blob = malloc(total);
    if(!blob){ free(ct); rv2_die("malloc blob"); }
    size_t o = 0;
    memcpy(blob + o, RV2_MAGIC, RV2_MAGIC_LEN);  o += RV2_MAGIC_LEN;
    blob[o++] = RV2_VERSION;
    uint64_t orig = (uint64_t)il;
    memcpy(blob + o, &orig, 8);                   o += 8;
    memcpy(blob + o, salt,  RV2_SALT_LEN);        o += RV2_SALT_LEN;
    memcpy(blob + o, nonce, RV2_NONCE_LEN);       o += RV2_NONCE_LEN;
    memcpy(blob + o, ct,    (size_t)cl);
    free(ct);
    *out_sz = total;
    return blob;
}

/* ================================================================== */
/* Decrypt RV2C blob → plaintext (heap-allocated, caller frees)        */
/* ================================================================== */
static uint8_t *rv2_decrypt_buf(const uint8_t *buf, size_t sz,
                                 const char *pw, size_t *plain_sz)
{
    if(sz < RV2_HDR_MIN) rv2_die("file too short to be RV2C");
    if(memcmp(buf, RV2_MAGIC, RV2_MAGIC_LEN) != 0) rv2_die("not an RV2C file");
    size_t o = RV2_MAGIC_LEN;
    if(buf[o] != RV2_VERSION){
        dprintf(STDERR_FILENO, "rv2: unsupported version %u\n", (unsigned)buf[o]);
        rv2_die("version mismatch");
    }
    o++;
    uint64_t orig_size;
    memcpy(&orig_size, buf + o, 8); o += 8;
    uint8_t salt[RV2_SALT_LEN], nonce[RV2_NONCE_LEN], key[RV2_KEY_LEN];
    memcpy(salt,  buf + o, RV2_SALT_LEN);  o += RV2_SALT_LEN;
    memcpy(nonce, buf + o, RV2_NONCE_LEN); o += RV2_NONCE_LEN;
    rv2_derive_key(key, pw, salt);
    size_t ctl = sz - o;
    uint8_t *plain = malloc(ctl);
    if(!plain){ sodium_memzero(key, RV2_KEY_LEN); rv2_die("malloc plain"); }
    unsigned long long dl;
    if(crypto_aead_aes256gcm_decrypt(plain, &dl, NULL,
                                     buf + o, ctl,
                                     NULL, 0, nonce, key) != 0){
        sodium_memzero(key, RV2_KEY_LEN); free(plain);
        rv2_die("decryption failed – wrong password or corrupt file");
    }
    sodium_memzero(key, RV2_KEY_LEN);
    *plain_sz = (size_t)orig_size;
    return plain;
}

/* ================================================================== */
/* Growable buffer                                                       */
/* ================================================================== */
typedef struct { uint8_t *d; size_t sz, cap; } RV2BB;
static void rv2bb_init(RV2BB *b){
    b->cap = 256 * 1024; b->sz = 0;
    b->d = malloc(b->cap); if(!b->d) rv2_die("malloc bb");
}
static void rv2bb_need(RV2BB *b, size_t extra){
    while(b->sz + extra > b->cap){
        b->cap *= 2;
        uint8_t *nb = realloc(b->d, b->cap);
        if(!nb) rv2_die("realloc bb");
        b->d = nb;
    }
}
static void rv2bb_app(RV2BB *b, const void *src, size_t n){
    rv2bb_need(b, n);
    memcpy(b->d + b->sz, src, n);
    b->sz += n;
}
static void rv2bb_free(RV2BB *b){
    sodium_memzero(b->d, b->sz);
    free(b->d); b->d = NULL; b->sz = b->cap = 0;
}

/* ================================================================== */
/* Container build: folder → flat blob                                  */
/*                                                                      */
/* Record format (repeated):                                            */
/*   [name_len u16][name][salt 16][nonce 12][enc_len u64][enc_data]    */
/* Sub-folders are recursed, containerised, then stored as a record    */
/* whose enc_data is the nested container blob (re-encrypted).         */
/* ================================================================== */
static void rv2_build_container(const char *folder, RV2BB *out, const char *pw);

static void rv2_build_container(const char *folder, RV2BB *out, const char *pw){
    DIR *d = opendir(folder);
    if(!d){
        dprintf(STDERR_FILENO, "rv2: opendir: %s (%s)\n", folder, strerror(errno));
        rv2_die("opendir");
    }
    struct dirent *e;
    while((e = readdir(d)) != NULL){
        if(!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char full[RV2_MAX_PATH];
        if(snprintf(full, sizeof(full), "%s/%s", folder, e->d_name) >= (int)sizeof(full))
            continue;
        
        /* FIX #2,#6: TOCTOU race condition and symlink attacks - use O_NOFOLLOW */
        int fd = open(full, O_RDONLY | O_NOFOLLOW);
        if (fd < 0) continue;
        struct stat st;
        if(fstat(fd, &st) != 0) { close(fd); continue; }

        uint8_t *payload = NULL;
        size_t   payload_sz = 0;

        if(S_ISDIR(st.st_mode)){
            close(fd); /* Can't read directory via file descriptor */
            RV2BB sub; rv2bb_init(&sub);
            rv2_build_container(full, &sub, pw);
            payload    = sub.d;
            payload_sz = sub.sz;
            sub.d = NULL;
            rv2bb_free(&sub);
        } else if(S_ISREG(st.st_mode)){
            /* Read from fd to avoid TOCTOU between stat and read */
            payload_sz = st.st_size;
            if (payload_sz > 0x40000000) { close(fd); continue; } /* 1GB limit */
            payload = malloc(payload_sz);
            if (!payload) { close(fd); rv2_die("malloc payload"); }
            ssize_t nr = read(fd, payload, payload_sz);
            close(fd);
            if (nr < 0 || (size_t)nr != payload_sz) { free(payload); continue; }
        } else {
            continue; /* skip symlinks, devices, etc. */
        }

        /* Encrypt the payload */
        uint8_t salt[RV2_SALT_LEN], nonce[RV2_NONCE_LEN], key[RV2_KEY_LEN];
        randombytes_buf(salt,  RV2_SALT_LEN);
        randombytes_buf(nonce, RV2_NONCE_LEN);
        rv2_derive_key(key, pw, salt);
        size_t ct_max = payload_sz + RV2_TAG_LEN;
        uint8_t *ct = malloc(ct_max);
        if(!ct){ sodium_memzero(key, RV2_KEY_LEN); free(payload); rv2_die("malloc ct"); }
        unsigned long long cl;
        if(crypto_aead_aes256gcm_encrypt(ct, &cl,
                                         payload, payload_sz,
                                         NULL, 0, NULL, nonce, key) != 0){
            sodium_memzero(key, RV2_KEY_LEN); free(ct); free(payload); rv2_die("encrypt");
        }
        sodium_memzero(key, RV2_KEY_LEN);
        sodium_memzero(payload, payload_sz); free(payload);

        /* Append record to output buffer */
        uint16_t nl = (uint16_t)strlen(e->d_name);
        uint8_t nl_b[2]; nl_b[0] = (uint8_t)nl; nl_b[1] = (uint8_t)(nl >> 8);
        uint8_t cl_b[8];
        for(int i = 0; i < 8; i++) cl_b[i] = (uint8_t)(cl >> (8*i));

        rv2bb_app(out, nl_b,    2);
        rv2bb_app(out, e->d_name, nl);
        rv2bb_app(out, salt,    RV2_SALT_LEN);
        rv2bb_app(out, nonce,   RV2_NONCE_LEN);
        rv2bb_app(out, cl_b,    8);
        rv2bb_app(out, ct,      (size_t)cl);
        free(ct);
    }
    closedir(d);
}

/* ================================================================== */
/* Encode                                                               */
/* ================================================================== */
static void rv2_encode_file(const char *path, const char *pw, int backup){
    size_t il; uint8_t *in = rv2_rfile(path, &il);
    if(backup){
        char bak[RV2_MAX_PATH];
        snprintf(bak, sizeof(bak), "%s.bak", path);
        rv2_wfile(bak, in, il);
        printf("rv2: backup: %s\n", bak);
    }
    size_t blob_sz; uint8_t *blob = rv2_encrypt_buf(in, il, pw, &blob_sz);
    sodium_memzero(in, il); free(in);
    rv2_wfile(path, blob, blob_sz);
    sodium_memzero(blob, blob_sz); free(blob);
    printf("rv2: encoded: %s\n", path);
}

static void rv2_encode_folder(const char *folder, const char *pw, int backup){
    /* Unused for folder encode, but accepted for API consistency */
    (void)backup;

    RV2BB cont; rv2bb_init(&cont);
    rv2_build_container(folder, &cont, pw);

    /* Wrap the whole container blob in one outer RV2C layer */
    size_t blob_sz; uint8_t *blob = rv2_encrypt_buf(cont.d, cont.sz, pw, &blob_sz);
    rv2bb_free(&cont);

    char out_path[RV2_MAX_PATH];
    snprintf(out_path, sizeof(out_path), "%s.rv2", folder);
    rv2_wfile(out_path, blob, blob_sz);
    sodium_memzero(blob, blob_sz); free(blob);
    printf("rv2: container: %s\n", out_path);
}

/* ================================================================== */
/* Decode                                                               */
/* ================================================================== */
static void rv2_decode_file(const char *path, const char *pw){
    size_t sz; uint8_t *buf = rv2_rfile(path, &sz);
    size_t pl; uint8_t *plain = rv2_decrypt_buf(buf, sz, pw, &pl);
    free(buf);
    rv2_wfile(path, plain, pl);
    sodium_memzero(plain, pl); free(plain);
    printf("rv2: decoded: %s\n", path);
}

/* Decode a container blob into out_dir (recursive) */
static void rv2_extract_container(const uint8_t *blob, size_t blob_sz,
                                   const char *out_dir, const char *pw);

static void rv2_extract_container(const uint8_t *blob, size_t blob_sz,
                                   const char *out_dir, const char *pw)
{
    if(mkdir(out_dir, 0755) != 0 && errno != EEXIST) rv2_die("mkdir");
    size_t o = 0;
    while(o + 2 <= blob_sz){
        /* FIX #3: Unvalidated deserialization - bound name_len */
        uint16_t nl = (uint16_t)blob[o] | ((uint16_t)blob[o+1] << 8); o += 2;
        /* Validate: name_len must fit in RV2_MAX_PATH and check for integer overflow */
        if (nl == 0 || nl > RV2_MAX_PATH - 1) break;
        if (o > blob_sz || o + nl > blob_sz) break;
        char name[RV2_MAX_PATH];
        memcpy(name, blob + o, nl); name[nl] = '\0'; o += nl;
        if(o + RV2_SALT_LEN + RV2_NONCE_LEN + 8 > blob_sz) break;
        uint8_t salt[RV2_SALT_LEN], nonce[RV2_NONCE_LEN], key[RV2_KEY_LEN];
        memcpy(salt,  blob + o, RV2_SALT_LEN);  o += RV2_SALT_LEN;
        memcpy(nonce, blob + o, RV2_NONCE_LEN); o += RV2_NONCE_LEN;
        uint64_t enc_len = 0;
        for(int i = 0; i < 8; i++) enc_len |= ((uint64_t)blob[o+i]) << (8*i); o += 8;
        if(o + enc_len > blob_sz) break;

        rv2_derive_key(key, pw, salt);
        size_t psz = (size_t)enc_len; /* upper bound */
        uint8_t *plain = malloc(psz);
        if(!plain){ sodium_memzero(key, RV2_KEY_LEN); rv2_die("malloc plain"); }
        unsigned long long dl;
        if(crypto_aead_aes256gcm_decrypt(plain, &dl, NULL,
                                         blob + o, (size_t)enc_len,
                                         NULL, 0, nonce, key) != 0){
            sodium_memzero(key, RV2_KEY_LEN); free(plain);
            rv2_die("decrypt record – wrong password or corrupt container");
        }
        sodium_memzero(key, RV2_KEY_LEN);
        o += (size_t)enc_len;

        char out_path[RV2_MAX_PATH];
        snprintf(out_path, sizeof(out_path), "%s/%s", out_dir, name);

        /* Heuristic: if the decrypted data starts with the inner container
           magic pattern (two-byte name_len at offset 0 that would be sane),
           treat as sub-folder; otherwise write as file.
           We probe: a valid sub-container must have a name_len < 256 at [0..1]
           followed by printable name bytes. Use a simple check. */
        int is_sub = 0;
        if(dl >= 3){
            uint16_t snl = (uint16_t)plain[0] | ((uint16_t)plain[1] << 8);
            if(snl > 0 && snl < 256 && dl > (size_t)(2 + snl)){
                /* all name bytes printable? */
                is_sub = 1;
                for(uint16_t i = 0; i < snl; i++){
                    uint8_t c = plain[2 + i];
                    if(c < 0x20 || c > 0x7E){ is_sub = 0; break; }
                }
            }
        }

        if(is_sub){
            rv2_extract_container(plain, (size_t)dl, out_path, pw);
        } else {
            rv2_wfile(out_path, plain, (size_t)dl);
        }
        sodium_memzero(plain, (size_t)dl); free(plain);
    }
}

static void rv2_decode_container(const char *path, const char *pw){
    size_t sz; uint8_t *buf = rv2_rfile(path, &sz);
    /* Outer RV2C layer */
    size_t pl; uint8_t *plain = rv2_decrypt_buf(buf, sz, pw, &pl);
    free(buf);

    /* Derive output directory name: strip .rv2 suffix if present */
    char out_dir[RV2_MAX_PATH];
    strncpy(out_dir, path, sizeof(out_dir) - 1); out_dir[sizeof(out_dir)-1] = '\0';
    char *suf = NULL;
    if((suf = strstr(out_dir, ".rv2")) != NULL && suf[4] == '\0') *suf = '\0';
    else snprintf(out_dir, sizeof(out_dir), "%s_decoded", path);

    printf("rv2: extracting to %s/\n", out_dir);
    rv2_extract_container(plain, pl, out_dir, pw);
    sodium_memzero(plain, pl); free(plain);
    printf("rv2: decoded container: %s/\n", out_dir);
}

/* ================================================================== */
/* Run – decrypt then exec via memfd (Linux) or temp file (fallback)   */
/* ================================================================== */
static int rv2_is_debugged(void){
#if defined(RV2_LINUX)
    return ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1;
#elif defined(RV2_MACOS)
    struct kinfo_proc info;
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    size_t size = sizeof(info);
    memset(&info, 0, sizeof(info));
    if(sysctl(mib, 4, &info, &size, NULL, 0) == -1) return 0;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
#else
    return 0;
#endif
}

static void rv2_run(const char *path, const char *pw){
    /* Security checks */
    struct utsname un; uname(&un);
    if(!strstr(un.machine, "x86_64") && !strstr(un.machine, "arm64"))
        rv2_die("unsupported CPU architecture");
    if(rv2_is_debugged())
        rv2_die("debugger detected");
    if(geteuid() == 0)
        rv2_die("refusing to run as root");

    size_t sz; uint8_t *buf = rv2_rfile(path, &sz);
    size_t pl; uint8_t *plain = rv2_decrypt_buf(buf, sz, pw, &pl);
    free(buf);

#if defined(RV2_LINUX)
    /* memfd: no file ever touches disk */
    int mfd = (int)syscall(SYS_memfd_create, ".", 1 /*MFD_CLOEXEC*/);
    if(mfd < 0) rv2_die("memfd_create");
    size_t done = 0;
    while(done < pl){
        ssize_t r = write(mfd, plain + done, pl - done);
        if(r <= 0){ close(mfd); rv2_die("memfd write"); }
        done += (size_t)r;
    }
    sodium_memzero(plain, pl); free(plain);
    char *const ea[] = { (char*)".", NULL };
    char *const ev[] = { NULL };
    pid_t pid = fork();
    if(pid < 0){ close(mfd); rv2_die("fork"); }
    if(pid == 0){ fexecve(mfd, ea, ev); _exit(127); }
    close(mfd);
    int st; waitpid(pid, &st, 0);
#else
    /* Fallback: write to a secure temp file, exec, then wipe */
    char tmp[] = "/tmp/rv2_XXXXXX";
    int fd = mkstemp(tmp);
    if(fd < 0){ sodium_memzero(plain, pl); free(plain); rv2_die("mkstemp"); }
    size_t done = 0;
    while(done < pl){
        ssize_t r = write(fd, plain + done, pl - done);
        if(r <= 0){ close(fd); unlink(tmp); rv2_die("write tmp"); }
        done += (size_t)r;
    }
    close(fd);
    if(chmod(tmp, 0700) != 0){ unlink(tmp); rv2_die("chmod tmp"); }
    sodium_memzero(plain, pl); free(plain);
    pid_t pid = fork();
    if(pid < 0){ unlink(tmp); rv2_die("fork"); }
    if(pid == 0){ execl(tmp, tmp, NULL); _exit(127); }
    int st; waitpid(pid, &st, 0);
    /* Wipe before unlink */
    {
        int wfd = open(tmp, O_WRONLY);
        if(wfd >= 0){
            uint8_t zero[4096]; memset(zero, 0, sizeof(zero));
            size_t pos = 0;
            while(pos < pl){ write(wfd, zero, sizeof(zero)); pos += sizeof(zero); }
            close(wfd);
        }
    }
    unlink(tmp);
#endif
}

/* ================================================================== */
/* Usage                                                                */
/* ================================================================== */
static void rv2_usage(const char *prog){
    dprintf(STDERR_FILENO,
        "RV v2 – Legacy Encrypted Container\n"
        "\n"
        "usage:\n"
        "  %s encode <file>    <password> [backup]   encrypt file in-place\n"
        "  %s encode <folder>  <password>             pack folder → <folder>.rv2\n"
        "  %s decode <file>    <password>             decrypt file in-place\n"
        "  %s decode <folder.rv2> <password>          extract container → folder/\n"
        "  %s run    <file>    <password>             decrypt & exec in memory\n"
        "\n"
        "notes:\n"
        "  'backup' keeps a .bak copy before encoding a single file\n"
        "  AES-256-GCM + Argon2id key derivation\n",
        prog, prog, prog, prog, prog);
}

/* ================================================================== */
/* SHAKE-256 / SHA3-512 (Keccak-f[1600])                               */
/* ================================================================== */

#define KECCAK_ROUNDS  24
#define SHA3_512_RATE   72
#define SHAKE256_RATE  136

typedef struct {
    uint64_t state[25];
    uint8_t  buf[200];
    size_t   buf_pos;
    size_t   rate;
    int      squeezing;
} shake_ctx;
typedef shake_ctx keccak_ctx;

static const uint64_t _keccak_rc[24] = {
    0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808AULL,
    0x8000000080008000ULL,0x000000000000808BULL,0x0000000080000001ULL,
    0x8000000080008081ULL,0x8000000000008009ULL,0x000000000000008AULL,
    0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000AULL,
    0x000000008000808BULL,0x800000000000008BULL,0x8000000000008089ULL,
    0x8000000000008003ULL,0x8000000000008002ULL,0x8000000000000080ULL,
    0x000000000000800AULL,0x800000008000000AULL,0x8000000080008081ULL,
    0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
};
static const int _keccak_rot[24] = {
    1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44
};
static const int _keccak_pi[24] = {
    10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1
};

#define ROT64(x,n) (((x)<<(n))|((x)>>(64-(n))))

/* ================================================================== */
/* Loading bar utility                                                 */
/* ================================================================== */
static void draw_progress(size_t current, size_t total) {
    if (total == 0) return;
    int bar_width = 40;
    float progress = (float)current / total;
    int filled = (int)(progress * bar_width);
    printf("\r[");
    for (int i = 0; i < bar_width; i++) {
        printf(i < filled ? "=" : " ");
    }
    printf("] %.1f%%", progress * 100.0);
    fflush(stdout);
}

static void keccak_f1600(uint64_t st[25]) {
    uint64_t t, bc[5];
    for (int r = 0; r < KECCAK_ROUNDS; r++) {
        for (int i=0;i<5;i++) bc[i]=st[i]^st[i+5]^st[i+10]^st[i+15]^st[i+20];
        for (int i=0;i<5;i++){t=bc[(i+4)%5]^ROT64(bc[(i+1)%5],1);for(int j=0;j<25;j+=5)st[j+i]^=t;}
        t=st[1]; for(int i=0;i<24;i++){int j=_keccak_pi[i];bc[0]=st[j];st[j]=ROT64(t,_keccak_rot[i]);t=bc[0];}
        for(int j=0;j<25;j+=5){
            for(int i=0;i<5;i++) bc[i]=st[j+i];
            for(int i=0;i<5;i++) st[j+i]=bc[i]^((~bc[(i+1)%5])&bc[(i+2)%5]);
        }
        st[0]^=_keccak_rc[r];
    }
}

static void shake256_init(shake_ctx *ctx) {
    memset(ctx,0,sizeof(*ctx)); ctx->rate=SHAKE256_RATE;
}
static void shake256_absorb(shake_ctx *ctx, const uint8_t *in, size_t len) {
    while (len > 0) {
        size_t take = ctx->rate - ctx->buf_pos;
        if (take > len) take = len;
        for (size_t i=0;i<take;i++) ctx->buf[ctx->buf_pos+i]^=in[i];
        ctx->buf_pos+=take; in+=take; len-=take;
        if (ctx->buf_pos==ctx->rate) {
            for (size_t i=0;i<ctx->rate/8;i++){uint64_t w=0;for(int b=0;b<8;b++)w|=((uint64_t)ctx->buf[i*8+b])<<(8*b);ctx->state[i]^=w;}
            keccak_f1600(ctx->state);
            memset(ctx->buf,0,ctx->rate); ctx->buf_pos=0;
        }
    }
}
static void shake256_finalize(shake_ctx *ctx) {
    ctx->buf[ctx->buf_pos]^=0x1F; ctx->buf[ctx->rate-1]^=0x80;
    for (size_t i=0;i<ctx->rate/8;i++){uint64_t w=0;for(int b=0;b<8;b++)w|=((uint64_t)ctx->buf[i*8+b])<<(8*b);ctx->state[i]^=w;}
    keccak_f1600(ctx->state);
    memset(ctx->buf,0,ctx->rate); ctx->buf_pos=0; ctx->squeezing=1;
}
static void shake256_squeeze(shake_ctx *ctx, uint8_t *out, size_t len) {
    if (!ctx->squeezing) shake256_finalize(ctx);
    while (len > 0) {
        if (ctx->buf_pos==0){for(size_t i=0;i<ctx->rate/8;i++){uint64_t w=ctx->state[i];for(int b=0;b<8;b++)ctx->buf[i*8+b]=(uint8_t)(w>>(8*b));}}
        size_t take=ctx->rate-ctx->buf_pos; if(take>len)take=len;
        memcpy(out,ctx->buf+ctx->buf_pos,take); ctx->buf_pos+=take;
        if(ctx->buf_pos==ctx->rate){keccak_f1600(ctx->state);memset(ctx->buf,0,ctx->rate);ctx->buf_pos=0;}
        out+=take; len-=take;
    }
}
static void shake256(uint8_t *out,size_t olen,const uint8_t *in,size_t ilen){
    shake_ctx c; shake256_init(&c); shake256_absorb(&c,in,ilen); shake256_finalize(&c); shake256_squeeze(&c,out,olen);
}
static void sha3_512(uint8_t out[64], const uint8_t *in, size_t ilen) {
    shake_ctx ctx; memset(&ctx,0,sizeof(ctx)); ctx.rate=SHA3_512_RATE;
    shake256_absorb(&ctx,in,ilen);
    ctx.buf[ctx.buf_pos]^=0x06; ctx.buf[ctx.rate-1]^=0x80;
    for(size_t i=0;i<ctx.rate/8;i++){uint64_t w=0;for(int b=0;b<8;b++)w|=((uint64_t)ctx.buf[i*8+b])<<(8*b);ctx.state[i]^=w;}
    keccak_f1600(ctx.state); ctx.squeezing=1;
    uint8_t buf[72]={0};
    for(size_t i=0;i<9;i++){uint64_t w=ctx.state[i];for(int b=0;b<8;b++)buf[i*8+b]=(uint8_t)(w>>(8*b));}
    memcpy(out,buf,64);
}
static void shake256_mac(uint8_t *out,size_t olen,const uint8_t *key,size_t klen,const uint8_t *msg,size_t mlen){
    shake_ctx c; shake256_init(&c);
    shake256_absorb(&c,key,klen); uint8_t sep=0x00; shake256_absorb(&c,&sep,1);
    shake256_absorb(&c,msg,mlen); shake256_finalize(&c); shake256_squeeze(&c,out,olen);
}

/* ================================================================== */
/* ML-KEM-1024 (FIPS 203, k=4)                                         */
/* ================================================================== */

#define KYBER_K       4
#define KYBER_N       256
#define KYBER_Q       3329
#define KYBER_ETA1    2
#define KYBER_ETA2    2
#define KYBER_DU      11
#define KYBER_DV      5
#define KYBER_POLYBYTES        384
#define KYBER_POLYVECBYTES     (KYBER_K * KYBER_POLYBYTES)
#define KYBER_POLYCOMPRESSEDBYTES_DU  352
#define KYBER_POLYCOMPRESSEDBYTES_DV  160
#define KYBER_POLYVECCOMPRESSEDBYTES  (KYBER_K * KYBER_POLYCOMPRESSEDBYTES_DU)
#define MLKEM1024_PUBLICKEYBYTES   1568
#define MLKEM1024_SECRETKEYBYTES   3168
#define MLKEM1024_CIPHERTEXTBYTES  1568
#define MLKEM1024_SHAREDSECRETBYTES  32
#define MLKEM1024_PK_BYTES   MLKEM1024_PUBLICKEYBYTES
#define MLKEM1024_SK_BYTES   MLKEM1024_SECRETKEYBYTES
#define MLKEM1024_CT_BYTES   MLKEM1024_CIPHERTEXTBYTES
#define MLKEM1024_SS_BYTES   MLKEM1024_SHAREDSECRETBYTES

typedef struct { int16_t coeffs[KYBER_N]; } kyber_poly;
typedef struct { kyber_poly vec[KYBER_K]; } kyber_polyvec;

static int16_t barrett_reduce(int32_t a) {
    int32_t t; const int32_t v=((1<<26)+KYBER_Q/2)/KYBER_Q;
    t=(int32_t)(((int64_t)v*a+(1<<25))>>26); t*=KYBER_Q;
    return (int16_t)(a-t);
}
static int16_t fqmul(int16_t a,int16_t b){return barrett_reduce((int32_t)a*b);}

static const int16_t _kyber_zetas[128]={
    2285,2571,2970,1812,1493,1422,287,202,3158,622,1577,182,962,2127,1855,1468,
    573,2004,264,383,2500,1458,1727,3199,2648,1017,732,608,1787,411,3124,1758,
    1223,652,2777,1015,2036,1491,3047,1785,516,3321,3009,2663,1711,2167,126,1469,
    2476,3239,3058,830,107,1908,3082,270,854,914,1883,3646,3812,3542,2232,3220,
    694,621,943,2261,2099,591,728,902,1489,1631,3459,448,411,478,663,1556,
    2166,2629,1516,800,866,1440,2477,744,2142,1169,2882,3421,658,338,550,2353,
    2507,2926,2461,3129,879,1617,2847,2729,1015,3053,2044,2677,3422,1490,2145,2167,
    2416,1380,1697,2757,1169,2474,3100,2178,869,2456,2660,975,1560,3305,2130,1867
};

static void kyber_ntt(kyber_poly *p) {
    int len,start,j,k=1; int16_t t,zeta;
    for(len=128;len>=2;len>>=1)
        for(start=0;start<256;start+=2*len){
            zeta=_kyber_zetas[k++];
            for(j=start;j<start+len;j++){
                t=fqmul(zeta,p->coeffs[j+len]);
                p->coeffs[j+len]=p->coeffs[j]-t;
                p->coeffs[j]=p->coeffs[j]+t;
            }
        }
}
static void kyber_invntt(kyber_poly *p) {
    int start,len,j,k=127; int16_t t,zeta;
    const int16_t f=1441;
    for(len=2;len<=128;len<<=1)
        for(start=0;start<256;start+=2*len){
            zeta=-_kyber_zetas[k--];
            for(j=start;j<start+len;j++){
                t=p->coeffs[j];
                p->coeffs[j]=barrett_reduce(t+p->coeffs[j+len]);
                p->coeffs[j+len]=fqmul(zeta,(int16_t)(p->coeffs[j+len]-t));
            }
        }
    for(j=0;j<256;j++) p->coeffs[j]=fqmul(p->coeffs[j],f);
}
static void kyber_basemul(kyber_poly *r,const kyber_poly *a,const kyber_poly *b,int zi) {
    for(int i=0;i<64;i++){
        int16_t z=_kyber_zetas[64+zi/2]; if(zi%2)z=-z;
        r->coeffs[2*i]=fqmul(a->coeffs[2*i+1],b->coeffs[2*i+1]);
        r->coeffs[2*i]=fqmul(r->coeffs[2*i],z);
        r->coeffs[2*i]+=fqmul(a->coeffs[2*i],b->coeffs[2*i]);
        r->coeffs[2*i+1]=fqmul(a->coeffs[2*i],b->coeffs[2*i+1]);
        r->coeffs[2*i+1]+=fqmul(a->coeffs[2*i+1],b->coeffs[2*i]);
    }
}
static void kyber_gen_matrix_entry(kyber_poly *a,const uint8_t rho[32],uint8_t i,uint8_t j){
    uint8_t seed[34]; memcpy(seed,rho,32); seed[32]=j; seed[33]=i;
    uint8_t xof[672]; shake_ctx ctx; shake256_init(&ctx);
    shake256_absorb(&ctx,seed,34); shake256_finalize(&ctx); shake256_squeeze(&ctx,xof,672);
    int cnt=0,pos=0;
    while(cnt<KYBER_N){
        if(pos+3>672)break;
        uint16_t d1=(uint16_t)(xof[pos]|((xof[pos+1]&0x0F)<<8));
        uint16_t d2=(uint16_t)((xof[pos+1]>>4)|((uint16_t)xof[pos+2]<<4));
        pos+=3;
        if(d1<KYBER_Q)a->coeffs[cnt++]=(int16_t)d1;
        if(d2<KYBER_Q&&cnt<KYBER_N)a->coeffs[cnt++]=(int16_t)d2;
    }
}
static void kyber_cbd2(kyber_poly *p,const uint8_t buf[128]){
    for(int i=0;i<64;i++){
        uint32_t t=(uint32_t)buf[2*i]|((uint32_t)buf[2*i+1]<<8);
        for(int j=0;j<8;j++){
            uint16_t a=(t>>j)&0x55,b=(t>>(j^1))&0x55;
            p->coeffs[8*i+j]=(int16_t)(__builtin_popcount(a)-__builtin_popcount(b));
        }
    }
}
static void kyber_polyvec_basemul_acc(kyber_poly *r,const kyber_polyvec *a,const kyber_polyvec *b){
    memset(r,0,sizeof(*r));
    for(int i=0;i<KYBER_K;i++)
        for(int j=0;j<64;j++){
            kyber_poly tmp; kyber_basemul(&tmp,&a->vec[i],&b->vec[i],2*j);
            r->coeffs[2*j]=barrett_reduce(r->coeffs[2*j]+tmp.coeffs[2*j]);
            r->coeffs[2*j+1]=barrett_reduce(r->coeffs[2*j+1]+tmp.coeffs[2*j+1]);
        }
}
static void kyber_polyvec_ntt(kyber_polyvec *v){for(int i=0;i<KYBER_K;i++)kyber_ntt(&v->vec[i]);}
static void kyber_polyvec_invntt(kyber_polyvec *v){for(int i=0;i<KYBER_K;i++)kyber_invntt(&v->vec[i]);}
static void kyber_poly_tobytes(uint8_t r[KYBER_POLYBYTES],const kyber_poly *a){
    for(int i=0;i<KYBER_N/2;i++){
        uint16_t t0=(uint16_t)(a->coeffs[2*i]%KYBER_Q),t1=(uint16_t)(a->coeffs[2*i+1]%KYBER_Q);
        r[3*i]=(uint8_t)t0; r[3*i+1]=(uint8_t)((t0>>8)|(t1<<4)); r[3*i+2]=(uint8_t)(t1>>4);
    }
}
static void kyber_poly_frombytes(kyber_poly *r,const uint8_t a[KYBER_POLYBYTES]){
    for(int i=0;i<KYBER_N/2;i++){
        r->coeffs[2*i]=(int16_t)((a[3*i]|(((uint16_t)a[3*i+1])<<8))&0xFFF);
        r->coeffs[2*i+1]=(int16_t)(((a[3*i+1]>>4)|(((uint16_t)a[3*i+2])<<4))&0xFFF);
    }
}
static void kyber_poly_compress_du(uint8_t r[],const kyber_poly *a){
    for(int i=0;i<KYBER_N/8;i++){
        uint16_t t[8];
        for(int j=0;j<8;j++) t[j]=(uint16_t)((((uint32_t)a->coeffs[8*i+j]<<KYBER_DU)+KYBER_Q/2)/KYBER_Q)&((1<<KYBER_DU)-1);
        r[11*i+0]=(uint8_t)t[0];r[11*i+1]=(uint8_t)((t[0]>>8)|(t[1]<<3));
        r[11*i+2]=(uint8_t)((t[1]>>5)|(t[2]<<6));r[11*i+3]=(uint8_t)(t[2]>>2);
        r[11*i+4]=(uint8_t)((t[2]>>10)|(t[3]<<1));r[11*i+5]=(uint8_t)((t[3]>>7)|(t[4]<<4));
        r[11*i+6]=(uint8_t)((t[4]>>4)|(t[5]<<7));r[11*i+7]=(uint8_t)(t[5]>>1);
        r[11*i+8]=(uint8_t)((t[5]>>9)|(t[6]<<2));r[11*i+9]=(uint8_t)((t[6]>>6)|(t[7]<<5));
        r[11*i+10]=(uint8_t)(t[7]>>3);
    }
}
static void kyber_poly_decompress_du(kyber_poly *r,const uint8_t a[]){
    for(int i=0;i<KYBER_N/8;i++){
        uint16_t t[8];
        t[0]=(uint16_t)(a[11*i+0]|(((uint16_t)a[11*i+1]&0x07)<<8));
        t[1]=(uint16_t)((a[11*i+1]>>3)|(((uint16_t)a[11*i+2]&0x3F)<<5));
        t[2]=(uint16_t)((a[11*i+2]>>6)|((uint16_t)a[11*i+3]<<2)|(((uint16_t)a[11*i+4]&0x01)<<10));
        t[3]=(uint16_t)((a[11*i+4]>>1)|(((uint16_t)a[11*i+5]&0x0F)<<7));
        t[4]=(uint16_t)((a[11*i+5]>>4)|(((uint16_t)a[11*i+6]&0x7F)<<4));
        t[5]=(uint16_t)((a[11*i+6]>>7)|((uint16_t)a[11*i+7]<<1)|(((uint16_t)a[11*i+8]&0x03)<<9));
        t[6]=(uint16_t)((a[11*i+8]>>2)|(((uint16_t)a[11*i+9]&0x1F)<<6));
        t[7]=(uint16_t)((a[11*i+9]>>5)|((uint16_t)a[11*i+10]<<3));
        for(int j=0;j<8;j++) r->coeffs[8*i+j]=(int16_t)(((uint32_t)t[j]*KYBER_Q+(1<<(KYBER_DU-1)))>>KYBER_DU);
    }
}
static void kyber_poly_compress_dv(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_DV],const kyber_poly *a){
    for(int i=0;i<KYBER_N/8;i++){
        uint8_t t[8];
        for(int j=0;j<8;j++) t[j]=(uint8_t)((((uint32_t)a->coeffs[8*i+j]<<KYBER_DV)+KYBER_Q/2)/KYBER_Q)&((1<<KYBER_DV)-1);
        r[5*i+0]=t[0]|(t[1]<<5); r[5*i+1]=(t[1]>>3)|(t[2]<<2)|(t[3]<<7);
        r[5*i+2]=(t[3]>>1)|(t[4]<<4); r[5*i+3]=(t[4]>>4)|(t[5]<<1)|(t[6]<<6);
        r[5*i+4]=(t[6]>>2)|(t[7]<<3);
    }
}
static void kyber_poly_decompress_dv(kyber_poly *r,const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_DV]){
    for(int i=0;i<KYBER_N/8;i++){
        r->coeffs[8*i+0]=(int16_t)((((uint16_t)(a[5*i+0]&31))*KYBER_Q+16)>>5);
        r->coeffs[8*i+1]=(int16_t)((((uint16_t)((a[5*i+0]>>5)|(a[5*i+1]&3)<<3))*KYBER_Q+16)>>5);
        r->coeffs[8*i+2]=(int16_t)((((uint16_t)((a[5*i+1]>>2)&31))*KYBER_Q+16)>>5);
        r->coeffs[8*i+3]=(int16_t)((((uint16_t)((a[5*i+1]>>7)|(a[5*i+2]&15)<<1))*KYBER_Q+16)>>5);
        r->coeffs[8*i+4]=(int16_t)((((uint16_t)((a[5*i+2]>>4)|(a[5*i+3]&1)<<4))*KYBER_Q+16)>>5);
        r->coeffs[8*i+5]=(int16_t)((((uint16_t)((a[5*i+3]>>1)&31))*KYBER_Q+16)>>5);
        r->coeffs[8*i+6]=(int16_t)((((uint16_t)((a[5*i+3]>>6)|(a[5*i+4]&7)<<2))*KYBER_Q+16)>>5);
        r->coeffs[8*i+7]=(int16_t)((((uint16_t)(a[5*i+4]>>3))*KYBER_Q+16)>>5);
    }
}
static void kyber_poly_frommsg(kyber_poly *r,const uint8_t msg[32]){
    for(int i=0;i<32;i++) for(int j=0;j<8;j++)
        r->coeffs[8*i+j]=(int16_t)(-((msg[i]>>j)&1))&(int16_t)((KYBER_Q+1)/2);
}
static void kyber_poly_tomsg(uint8_t msg[32],const kyber_poly *a){
    memset(msg,0,32);
    for(int i=0;i<KYBER_N;i++){
        uint16_t t=(uint16_t)((((uint32_t)a->coeffs[i]<<1)+KYBER_Q/2)/KYBER_Q)&1;
        msg[i/8]|=(uint8_t)(t<<(i%8));
    }
}

static void ml_kem1024_keygen(uint8_t pk[MLKEM1024_PUBLICKEYBYTES],
                               uint8_t sk[MLKEM1024_SECRETKEYBYTES]) {
    uint8_t d[64]; randombytes_buf(d,64);
    uint8_t rs[64]; sha3_512(rs,d,32);
    uint8_t *rho=rs, *sigma=rs+32;
    kyber_polyvec A[KYBER_K];
    for(int i=0;i<KYBER_K;i++) for(int j=0;j<KYBER_K;j++) kyber_gen_matrix_entry(&A[i].vec[j],rho,(uint8_t)i,(uint8_t)j);
    kyber_polyvec s,e;
    for(int i=0;i<KYBER_K;i++){uint8_t buf[128],seed[33];memcpy(seed,sigma,32);seed[32]=(uint8_t)i;shake256(buf,128,seed,33);kyber_cbd2(&s.vec[i],buf);}
    for(int i=0;i<KYBER_K;i++){uint8_t buf[128],seed[33];memcpy(seed,sigma,32);seed[32]=(uint8_t)(KYBER_K+i);shake256(buf,128,seed,33);kyber_cbd2(&e.vec[i],buf);}
    kyber_polyvec_ntt(&s); kyber_polyvec_ntt(&e);
    kyber_polyvec t;
    for(int i=0;i<KYBER_K;i++){
        kyber_polyvec_basemul_acc(&t.vec[i],&A[i],&s);
        for(int j=0;j<KYBER_N;j++) t.vec[i].coeffs[j]=barrett_reduce(t.vec[i].coeffs[j]+e.vec[i].coeffs[j]);
    }
    for(int i=0;i<KYBER_K;i++) kyber_poly_tobytes(pk+i*KYBER_POLYBYTES,&t.vec[i]);
    memcpy(pk+KYBER_K*KYBER_POLYBYTES,rho,32);
    for(int i=0;i<KYBER_K;i++) kyber_poly_tobytes(sk+i*KYBER_POLYBYTES,&s.vec[i]);
    memcpy(sk+KYBER_POLYVECBYTES,pk,MLKEM1024_PUBLICKEYBYTES);
    shake256(sk+KYBER_POLYVECBYTES+MLKEM1024_PUBLICKEYBYTES,32,pk,MLKEM1024_PUBLICKEYBYTES);
    randombytes_buf(sk+KYBER_POLYVECBYTES+MLKEM1024_PUBLICKEYBYTES+32,32);
    sodium_memzero(d,sizeof(d)); sodium_memzero(&s,sizeof(s)); sodium_memzero(&e,sizeof(e));
}

static void ml_kem1024_enc(uint8_t ct[MLKEM1024_CIPHERTEXTBYTES],
                            uint8_t ss[MLKEM1024_SHAREDSECRETBYTES],
                            const uint8_t pk[MLKEM1024_PUBLICKEYBYTES]) {
    uint8_t m[32]; randombytes_buf(m,32);
    uint8_t hpk[32]; shake256(hpk,32,pk,MLKEM1024_PUBLICKEYBYTES);
    uint8_t inp[64]; memcpy(inp,m,32); memcpy(inp+32,hpk,32);
    uint8_t kr[64]; sha3_512(kr,inp,64);
    uint8_t *r=kr+32;
    kyber_polyvec t; for(int i=0;i<KYBER_K;i++) kyber_poly_frombytes(&t.vec[i],pk+i*KYBER_POLYBYTES);
    uint8_t *rho=(uint8_t*)pk+KYBER_K*KYBER_POLYBYTES;
    kyber_polyvec AT[KYBER_K];
    for(int i=0;i<KYBER_K;i++) for(int j=0;j<KYBER_K;j++) kyber_gen_matrix_entry(&AT[i].vec[j],rho,(uint8_t)j,(uint8_t)i);
    kyber_polyvec rv,e1; kyber_poly e2;
    for(int i=0;i<KYBER_K;i++){uint8_t buf[128],seed[33];memcpy(seed,r,32);seed[32]=(uint8_t)i;shake256(buf,128,seed,33);kyber_cbd2(&rv.vec[i],buf);}
    for(int i=0;i<KYBER_K;i++){uint8_t buf[128],seed[33];memcpy(seed,r,32);seed[32]=(uint8_t)(KYBER_K+i);shake256(buf,128,seed,33);kyber_cbd2(&e1.vec[i],buf);}
    {uint8_t buf[128],seed[33];memcpy(seed,r,32);seed[32]=(uint8_t)(2*KYBER_K);shake256(buf,128,seed,33);kyber_cbd2(&e2,buf);}
    kyber_polyvec_ntt(&rv);
    kyber_polyvec u;
    for(int i=0;i<KYBER_K;i++){kyber_polyvec_basemul_acc(&u.vec[i],&AT[i],&rv);kyber_invntt(&u.vec[i]);for(int j=0;j<KYBER_N;j++)u.vec[i].coeffs[j]=barrett_reduce(u.vec[i].coeffs[j]+e1.vec[i].coeffs[j]);}
    kyber_poly v,mp;
    kyber_polyvec_basemul_acc(&v,&t,&rv); kyber_invntt(&v);
    kyber_poly_frommsg(&mp,m);
    for(int j=0;j<KYBER_N;j++) v.coeffs[j]=barrett_reduce(v.coeffs[j]+e2.coeffs[j]+mp.coeffs[j]);
    for(int i=0;i<KYBER_K;i++) kyber_poly_compress_du(ct+i*KYBER_POLYCOMPRESSEDBYTES_DU,&u.vec[i]);
    kyber_poly_compress_dv(ct+KYBER_POLYVECCOMPRESSEDBYTES,&v);
    uint8_t hct[32]; shake256(hct,32,ct,MLKEM1024_CIPHERTEXTBYTES);
    uint8_t kdf[64]; memcpy(kdf,kr,32); memcpy(kdf+32,hct,32);
    shake256(ss,32,kdf,64);
    sodium_memzero(m,sizeof(m)); sodium_memzero(kr,sizeof(kr));
    sodium_memzero(&rv,sizeof(rv)); sodium_memzero(&e1,sizeof(e1));
}

static void ml_kem1024_dec(uint8_t ss[MLKEM1024_SHAREDSECRETBYTES],
                            const uint8_t ct[MLKEM1024_CIPHERTEXTBYTES],
                            const uint8_t sk[MLKEM1024_SECRETKEYBYTES]) {
    const uint8_t *sk_s=sk, *pk=sk+KYBER_POLYVECBYTES;
    const uint8_t *hpk=pk+MLKEM1024_PUBLICKEYBYTES, *z=hpk+32;
    kyber_polyvec s; for(int i=0;i<KYBER_K;i++) kyber_poly_frombytes(&s.vec[i],sk_s+i*KYBER_POLYBYTES);
    kyber_polyvec_ntt(&s);
    kyber_polyvec u; kyber_poly v;
    for(int i=0;i<KYBER_K;i++) kyber_poly_decompress_du(&u.vec[i],ct+i*KYBER_POLYCOMPRESSEDBYTES_DU);
    kyber_poly_decompress_dv(&v,ct+KYBER_POLYVECCOMPRESSEDBYTES);
    kyber_polyvec_ntt(&u);
    kyber_poly mp; kyber_polyvec_basemul_acc(&mp,&s,&u); kyber_invntt(&mp);
    for(int j=0;j<KYBER_N;j++) mp.coeffs[j]=barrett_reduce(v.coeffs[j]-mp.coeffs[j]);
    uint8_t m[32]; kyber_poly_tomsg(m,&mp);
    uint8_t inp[64]; memcpy(inp,m,32); memcpy(inp+32,hpk,32);
    uint8_t kr[64]; sha3_512(kr,inp,64);
    /* Re-encrypt with m' for implicit rejection */
    uint8_t ct2[MLKEM1024_CIPHERTEXTBYTES];
    {
        const uint8_t *r2=kr+32;
        kyber_polyvec t2; for(int i=0;i<KYBER_K;i++) kyber_poly_frombytes(&t2.vec[i],pk+i*KYBER_POLYBYTES);
        uint8_t *rho2=(uint8_t*)pk+KYBER_K*KYBER_POLYBYTES;
        kyber_polyvec AT2[KYBER_K];
        for(int i=0;i<KYBER_K;i++) for(int j=0;j<KYBER_K;j++) kyber_gen_matrix_entry(&AT2[i].vec[j],rho2,(uint8_t)j,(uint8_t)i);
        kyber_polyvec rv2,e12; kyber_poly e22,mp2,v2,u2v[KYBER_K];
        for(int i=0;i<KYBER_K;i++){uint8_t buf[128],seed[33];memcpy(seed,r2,32);seed[32]=(uint8_t)i;shake256(buf,128,seed,33);kyber_cbd2(&rv2.vec[i],buf);}
        for(int i=0;i<KYBER_K;i++){uint8_t buf[128],seed[33];memcpy(seed,r2,32);seed[32]=(uint8_t)(KYBER_K+i);shake256(buf,128,seed,33);kyber_cbd2(&e12.vec[i],buf);}
        {uint8_t buf[128],seed[33];memcpy(seed,r2,32);seed[32]=(uint8_t)(2*KYBER_K);shake256(buf,128,seed,33);kyber_cbd2(&e22,buf);}
        kyber_polyvec_ntt(&rv2);
        for(int i=0;i<KYBER_K;i++){kyber_polyvec_basemul_acc(&u2v[i],&AT2[i],&rv2);kyber_invntt(&u2v[i]);for(int j=0;j<KYBER_N;j++)u2v[i].coeffs[j]=barrett_reduce(u2v[i].coeffs[j]+e12.vec[i].coeffs[j]);}
        kyber_polyvec_basemul_acc(&v2,&t2,&rv2); kyber_invntt(&v2);
        kyber_poly_frommsg(&mp2,m);
        for(int j=0;j<KYBER_N;j++) v2.coeffs[j]=barrett_reduce(v2.coeffs[j]+e22.coeffs[j]+mp2.coeffs[j]);
        for(int i=0;i<KYBER_K;i++) kyber_poly_compress_du(ct2+i*KYBER_POLYCOMPRESSEDBYTES_DU,&u2v[i]);
        kyber_poly_compress_dv(ct2+KYBER_POLYVECCOMPRESSEDBYTES,&v2);
    }
    uint8_t hct[32]; shake256(hct,32,ct,MLKEM1024_CIPHERTEXTBYTES);
    int match=sodium_memcmp(ct,ct2,MLKEM1024_CIPHERTEXTBYTES)==0;
    uint8_t kdf[64];
    if(match) memcpy(kdf,kr,32);
    else       shake256(kdf,32,z,32);
    memcpy(kdf+32,hct,32);
    shake256(ss,32,kdf,64);
    sodium_memzero(m,sizeof(m)); sodium_memzero(kr,sizeof(kr)); sodium_memzero(&s,sizeof(s));
}

static void hybrid_kdf(uint8_t *out,size_t klen,const uint8_t ak[32],const uint8_t ss[32],const uint8_t *ctx,size_t clen){
    shake_ctx c; shake256_init(&c);
    const uint8_t dom[]="rv5-hybrid-kdf-v1";
    shake256_absorb(&c,dom,sizeof(dom)-1);
    shake256_absorb(&c,ak,32); shake256_absorb(&c,ss,32);
    if(ctx&&clen) shake256_absorb(&c,ctx,clen);
    shake256_finalize(&c); shake256_squeeze(&c,out,klen);
}

/* ================================================================== */
/* Timestamp counter                                                    */
/* ================================================================== */
static inline uint64_t plat_rdtsc(void) {
#if defined(__x86_64__)
    uint32_t lo,hi;
    __asm__ __volatile__("xorl %%eax,%%eax\ncpuid\nrdtsc":"=a"(lo),"=d"(hi)::"%rbx","%rcx");
    return ((uint64_t)hi<<32)|lo;
#elif defined(__aarch64__)
    uint64_t t; __asm__ __volatile__("mrs %0, cntvct_el0":"=r"(t)); return t;
#else
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return (uint64_t)ts.tv_sec*1000000000ULL+(uint64_t)ts.tv_nsec;
#endif
}

/* ================================================================== */
/* Secure memory                                                        */
/* ================================================================== */
static inline uint8_t *plat_secure_alloc(size_t n){
    void *p=mmap(NULL,n,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_PRIVATE,-1,0);
    if(p==MAP_FAILED)return NULL; mlock(p,n); return (uint8_t*)p;
}
static inline void plat_secure_free(uint8_t *p,size_t n){
    if(!p||!n)return; sodium_memzero(p,n); munlock(p,n); munmap(p,n);
}

/* ================================================================== */
/* Secure wipe registry — zeroes all registered regions on SIGINT/     */
/* SIGTERM so key material never remains in RAM after forced exit.     */
/* ================================================================== */
#include <signal.h>
#define WIPE_MAX 512
typedef struct { volatile uint8_t *ptr; size_t len; } WipeEntry;
static WipeEntry         _wipe_table[WIPE_MAX];
static volatile int      _wipe_cnt = 0;
static pthread_mutex_t   _wipe_mu  = PTHREAD_MUTEX_INITIALIZER;

static void wipe_register(volatile uint8_t *ptr, size_t len){
    pthread_mutex_lock(&_wipe_mu);
    if(_wipe_cnt < WIPE_MAX){ _wipe_table[_wipe_cnt].ptr=ptr; _wipe_table[_wipe_cnt].len=len; _wipe_cnt++; }
    else { dprintf(STDERR_FILENO,"rv: wipe table full — increase WIPE_MAX\n"); _exit(1); }
    pthread_mutex_unlock(&_wipe_mu);
}
static void wipe_unregister(volatile uint8_t *ptr){
    pthread_mutex_lock(&_wipe_mu);
    for(int i=0;i<_wipe_cnt;i++) if(_wipe_table[i].ptr==ptr){ _wipe_table[i]=_wipe_table[--_wipe_cnt]; break; }
    pthread_mutex_unlock(&_wipe_mu);
}
static void _sig_wipe_handler(int sig){
    (void)sig;
    for(int i=0;i<_wipe_cnt;i++){
        volatile uint8_t *p=_wipe_table[i].ptr; size_t n=_wipe_table[i].len;
        for(size_t j=0;j<n;j++) p[j]=0;
    }
    _exit(130);
}
static void wipe_handler_install(void){
    struct sigaction sa; memset(&sa,0,sizeof(sa));
    sa.sa_handler=_sig_wipe_handler; sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,&sa,NULL); sigaction(SIGTERM,&sa,NULL);
}

static int are_debugged(void) {
#if defined(PTRACE_TRACEME)
    if(ptrace(PTRACE_TRACEME,0,NULL,0)==-1) return 1;
    ptrace(PTRACE_DETACH,getpid(),NULL,0);
#endif
    /* /proc/self/status TracerPid (Linux) */
    { FILE *f=fopen("/proc/self/status","r");
      if(f){char l[128];
        while(fgets(l,sizeof(l),f))
          if(!strncmp(l,"TracerPid:",10)){fclose(f);return atoi(l+10)!=0;}
        fclose(f);}}
    /* parent comm name (Linux) */
    { char pp[64]; snprintf(pp,sizeof(pp),"/proc/%d/comm",getppid());
      FILE *f=fopen(pp,"r");
      if(f){char n[64]={0};
        if(fgets(n,sizeof(n),f)){
          const char *db[]={"gdb","lldb","strace","ltrace","radare2","r2","frida","valgrind",NULL};
          for(int i=0;db[i];i++) if(strstr(n,db[i])){fclose(f);return 1;}
        } fclose(f);}}
    return 0;
}

/* ================================================================== */
/* VM detection                                                         */
/* ================================================================== */
static int plat_is_vm(void) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int a=0,b=0,c=0,d=0;
    if(__get_cpuid(1,&a,&b,&c,&d)&&(c&(1u<<31))) return 1;
    { __get_cpuid(0x40000000,&a,&b,&c,&d);
      char v[13]={0}; memcpy(v,&b,4); memcpy(v+4,&c,4); memcpy(v+8,&d,4);
      const char *hv[]={"KVMKVMKVM","VMwareVMware","VBoxVBoxVBox","XenVMMXenVMM","Microsoft Hv","TCGTCGTCGTCG","bhyve bhyve ","ACRNACRNACRN",NULL};
      for(int i=0;hv[i];i++) if(!strncmp(v,hv[i],strlen(hv[i]))) return 1; }
#endif
    /* /proc/cpuinfo hypervisor flag (Linux) */
    { FILE *f=fopen("/proc/cpuinfo","r");
      if(f){char l[256];while(fgets(l,256,f))if(strstr(l,"hypervisor")){fclose(f);return 1;}fclose(f);}}
    /* DMI strings (Linux) */
    { const char *dp[]={"/sys/class/dmi/id/sys_vendor","/sys/class/dmi/id/product_name","/sys/class/dmi/id/board_vendor",NULL};
      const char *vs[]={"QEMU","KVM","VirtualBox","VMware","Xen","Amazon EC2","Google Compute Engine","DigitalOcean","Linode","Vultr","Hetzner","OVHcloud","bhyve","OpenStack","innotek",NULL};
      for(int i=0;dp[i];i++){
        FILE *f=fopen(dp[i],"r");if(!f)continue;
        char buf[256]={0};
        if(fgets(buf,256,f)) for(int j=0;vs[j];j++) if(strstr(buf,vs[j])){fclose(f);return 1;}
        fclose(f);}}
    return 0;
}

/* ================================================================== */
/* Self-integrity check (.text SHA-256)                                 */
/* Linux/ELF only. ELF types inlined — no libelf or elf.h needed.     */
/* On non-Linux the check is a no-op (hash slot stays zeroed → skip). */
/* ================================================================== */

/* Minimal ELF64 types — only what we need, guarded against elf.h. */
#ifndef ELFMAG
# define ELFMAG      "\177ELF"
# define SELFMAG     4
# define EI_CLASS    4
# define ELFCLASS64  2
typedef uint16_t RV_Elf64_Half;
typedef uint32_t RV_Elf64_Word;
typedef uint64_t RV_Elf64_Off;
typedef uint64_t RV_Elf64_Addr;
typedef uint64_t RV_Elf64_Xword;
typedef struct {
    unsigned char    e_ident[16];
    RV_Elf64_Half    e_type, e_machine;
    RV_Elf64_Word    e_version;
    RV_Elf64_Addr    e_entry;
    RV_Elf64_Off     e_phoff, e_shoff;
    RV_Elf64_Word    e_flags;
    RV_Elf64_Half    e_ehsize, e_phentsize, e_phnum;
    RV_Elf64_Half    e_shentsize, e_shnum, e_shstrndx;
} RV_Elf64_Ehdr;
typedef struct {
    RV_Elf64_Word    sh_name, sh_type;
    RV_Elf64_Xword   sh_flags;
    RV_Elf64_Addr    sh_addr;
    RV_Elf64_Off     sh_offset;
    RV_Elf64_Xword   sh_size, sh_link, sh_info, sh_addralign, sh_entsize;
} RV_Elf64_Shdr;
#else
/* elf.h was somehow included — alias our names to the system types */
typedef Elf64_Ehdr RV_Elf64_Ehdr;
typedef Elf64_Shdr RV_Elf64_Shdr;
#endif

/* Portable attribute for injected text hash.
 * macOS (Mach-O) requires a "segment,section" format. ELF targets use ".rodata".
 */
#if defined(__APPLE__) && defined(__MACH__)
# define RV_TEXT_HASH_ATTR __attribute__((section("__DATA,__const"))) __attribute__((used))
#else
# define RV_TEXT_HASH_ATTR __attribute__((section(".rodata"))) __attribute__((used))
#endif

const uint8_t __rv_text_hash[32] RV_TEXT_HASH_ATTR = {0};

static void self_integrity_check(void) {
    /* All-zero hash means inject_hash.py hasn't run yet — skip */
    if(__rv_text_hash[0]==0 && __rv_text_hash[31]==0) return;
#ifdef __linux__
    int fd=open("/proc/self/exe",O_RDONLY); if(fd<0)return;
    struct stat st; if(fstat(fd,&st)!=0){close(fd);return;}
    void *base=mmap(NULL,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    close(fd); if(base==MAP_FAILED)return;
    uint8_t *elf=(uint8_t*)base;
    RV_Elf64_Ehdr *eh=(RV_Elf64_Ehdr*)elf;
    if(memcmp(eh->e_ident,ELFMAG,SELFMAG)!=0 ||
       eh->e_ident[EI_CLASS]!=ELFCLASS64 ||
       eh->e_shoff==0 || eh->e_shnum==0 ||
       eh->e_shstrndx>=eh->e_shnum){
        munmap(base,(size_t)st.st_size); return;
    }
    RV_Elf64_Shdr *sh=(RV_Elf64_Shdr*)(elf+eh->e_shoff);
    const char *ss=(const char*)(elf+sh[eh->e_shstrndx].sh_offset);
    const uint8_t *td=NULL; size_t ts=0;
    for(int i=0;i<eh->e_shnum;i++)
        if(!strcmp(ss+sh[i].sh_name,".text")){td=elf+sh[i].sh_offset;ts=(size_t)sh[i].sh_size;break;}
    if(!td||!ts){munmap(base,(size_t)st.st_size);return;}
    uint8_t got[32]; crypto_hash_sha256(got,td,ts);
    munmap(base,(size_t)st.st_size);
    if(crypto_verify_32(got,__rv_text_hash)!=0){
        volatile uint8_t p[64]; randombytes_buf((void*)p,64); _exit(1);
    }
#endif /* __linux__ */
}

/* ================================================================== */
/* Anti-RE macros                                                       */
/* ================================================================== */
#ifndef STRKEY
#define STRKEY 0xA7
#endif
#define _SC(c,i) ((uint8_t)((c)^(STRKEY^((i)*0x6B)^((i)>>2))))
#define _E(s,i)  (((i)<(int)(sizeof(s)-1))?(int)_SC((uint8_t)(s)[i],i):0)
#define _EB(s) \
  _E(s,0),_E(s,1),_E(s,2),_E(s,3),_E(s,4),_E(s,5),_E(s,6),_E(s,7),       \
  _E(s,8),_E(s,9),_E(s,10),_E(s,11),_E(s,12),_E(s,13),_E(s,14),_E(s,15),  \
  _E(s,16),_E(s,17),_E(s,18),_E(s,19),_E(s,20),_E(s,21),_E(s,22),_E(s,23),\
  _E(s,24),_E(s,25),_E(s,26),_E(s,27),_E(s,28),_E(s,29),_E(s,30),_E(s,31),\
  _E(s,32),_E(s,33),_E(s,34),_E(s,35),_E(s,36),_E(s,37),_E(s,38),_E(s,39),\
  _E(s,40),_E(s,41),_E(s,42),_E(s,43),_E(s,44),_E(s,45),_E(s,46),_E(s,47),\
  0
#define DECSTR(v,s) \
  static const uint8_t _enc_##v[]={_EB(s)}; \
  char v[sizeof(_enc_##v)]; \
  do{ for(size_t _i=0;_i<sizeof(_enc_##v)-1;_i++) \
        v[_i]=(char)(_enc_##v[_i]^(STRKEY^((_i)*0x6B)^((_i)>>2))); \
      v[sizeof(_enc_##v)-1]='\0'; }while(0)

#if defined(__x86_64__) || defined(__i386__)
# define ANTIDIS_TRAP()  __asm__ __volatile__("jmp 1f\n\t.byte 0xFF,0x15\n\t1:\n\t":::)
# define ANTIDIS_TRAP2() __asm__ __volatile__("jmp 2f\n\t.byte 0x48,0xFF,0x14,0x25\n\t2:\n\t":::)
#else
# define ANTIDIS_TRAP()  do{}while(0)
# define ANTIDIS_TRAP2() do{}while(0)
#endif

static volatile uint64_t _op_seed=0;
static inline void op_init(void){_op_seed=(uint64_t)plat_rdtsc()|1ULL;}
#define OP_FALSE ((_op_seed*(_op_seed+1))%2!=0)
#define DEAD_BRANCH(code) do{if(OP_FALSE){code;}}while(0)

static inline void _fake_noise_impl(void){
    uint8_t fb[64],fk[32],fn[12];
    randombytes_buf(fb,64); randombytes_buf(fk,32); randombytes_buf(fn,12);
    unsigned long long fl;
    crypto_aead_aes256gcm_encrypt(fb,&fl,fb,32,NULL,0,NULL,fn,fk);
    sodium_memzero(fb,64);
}
#define FAKE_CRYPTO_NOISE() DEAD_BRANCH(_fake_noise_impl())

#define STACK_CANARY_INIT()  uint8_t _can[16]; randombytes_buf(_can,16)
#define STACK_CANARY_SAVE()  uint8_t _can2[16]; memcpy(_can2,_can,16)
#define STACK_CANARY_CHECK() do{if(sodium_memcmp(_can,_can2,16)!=0){sodium_memzero(_can,16);_exit(1);}}while(0)
#define RE_GUARD() do{ANTIDIS_TRAP();FAKE_CRYPTO_NOISE();if(are_debugged())_exit(1);}while(0)

static void anti_re_init(void){
    ANTIDIS_TRAP(); op_init(); ANTIDIS_TRAP2(); FAKE_CRYPTO_NOISE();
    self_integrity_check(); ANTIDIS_TRAP();
}

/* ================================================================== */
/* Constants                                                            */
/* ================================================================== */
static const uint8_t _MAGIC_ENC[8]={0x52^0x23,0x56^0x23,0x35^0x23,0x43^0x23,0xDE^0x23,0xAD^0x23,0xBE^0x23,0xEF^0x23};
#define MAGIC_LEN  8
#define MAGIC_XK   0x23
#define VERSION    ((uint8_t)5)
static void get_magic(uint8_t o[8]){for(int i=0;i<8;i++)o[i]=_MAGIC_ENC[i]^MAGIC_XK;}

static const uint8_t _OTCM_ENC[4]={0x52^0x61,0x56^0x61,0x35^0x61,0x4F^0x61};
#define OTCM_XK 0x61
static void get_otcm(uint8_t o[4]){for(int i=0;i<4;i++)o[i]=_OTCM_ENC[i]^OTCM_XK;}

#define SALT_LEN   crypto_pwhash_SALTBYTES
#define NONCE_LEN  crypto_aead_aes256gcm_NPUBBYTES
#define KEY_LEN    crypto_aead_aes256gcm_KEYBYTES
#define TAG_LEN    crypto_aead_aes256gcm_ABYTES
#define MAC_LEN    64
#define PQHASH_LEN 64
#define OTC_LEN    32
#define OTC_ENC_LEN (SALT_LEN+NONCE_LEN+OTC_LEN+TAG_LEN)
#define US_LEN     32
#define US_ENC_LEN (SALT_LEN+NONCE_LEN+US_LEN+TAG_LEN)
#define SK_ENC_LEN (SALT_LEN+NONCE_LEN+MLKEM1024_SK_BYTES+TAG_LEN)
#define OTC_MPW_LEN 43
#define HWID_BUF   8192
#define MANIFEST_LEN (4+4+PQHASH_LEN+US_ENC_LEN+SK_ENC_LEN+MLKEM1024_CT_BYTES)
#define MAX_PATH_LEN 4096
#define MAX_PW_LEN   256
#define MAX_NAME_LEN 255

/* OTC layer: XChaCha20-Poly1305 (no AES-NI required) */
#define OTC_NONCE_LEN  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define OTC_TAG_LEN    crypto_aead_xchacha20poly1305_ietf_ABYTES
#define OTC_KEY_LEN    crypto_aead_xchacha20poly1305_ietf_KEYBYTES

#define FILE_PW_LEN   30
#define CONT_PW_LEN   30
#define ROOT_PW_LEN   30
#define FILES_PER_CONT_DEFAULT 3
static int g_files_per_cont = FILES_PER_CONT_DEFAULT;

static const char B62[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/* ================================================================== */
/* LE helpers                                                           */
/* ================================================================== */
static inline void w16(uint8_t*p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static inline void w32(uint8_t*p,uint32_t v){for(int i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static inline void w64(uint8_t*p,uint64_t v){for(int i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i));}
static inline uint16_t r16(const uint8_t*p){return(uint16_t)p[0]|((uint16_t)p[1]<<8);}
static inline uint32_t r32(const uint8_t*p){uint32_t v=0;for(int i=0;i<4;i++)v|=((uint32_t)p[i])<<(8*i);return v;}
static inline uint64_t r64(const uint8_t*p){uint64_t v=0;for(int i=0;i<8;i++)v|=((uint64_t)p[i])<<(8*i);return v;}

/* ================================================================== */
/* Error / secure alloc helpers                                         */
/* ================================================================== */
__attribute__((noreturn)) static void die(const char *m){
    dprintf(STDERR_FILENO,"rv: error: %s\n",m); _exit(1);
}
static uint8_t *sa(size_t n){uint8_t *p=plat_secure_alloc(n);if(!p)die("M");return p;}
static void sf(uint8_t *p,size_t n){plat_secure_free(p,n);}

/* ================================================================== */
/* TTY password reader                                                  */
/* ================================================================== */
static void read_pw(char *buf,size_t bl,const char *prompt){
    FILE *t=fopen("/dev/tty","r+"); if(!t)die("T");
    fputs(prompt,t); fflush(t);
    struct termios old,ne; tcgetattr(fileno(t),&old); ne=old;
    ne.c_lflag&=~(tcflag_t)(ECHO|ECHOE|ECHOK|ECHONL);
    tcsetattr(fileno(t),TCSANOW,&ne);
    if(!fgets(buf,(int)bl,t)){tcsetattr(fileno(t),TCSANOW,&old);fclose(t);die("P");}
    tcsetattr(fileno(t),TCSANOW,&old); fputc('\n',t); fclose(t);
    size_t l=strlen(buf); if(l>0&&buf[l-1]=='\n')buf[--l]='\0'; if(!l)die("E");
}

/* ================================================================== */
/* File I/O                                                             */
/* ================================================================== */
static uint8_t *rfile(const char *path,size_t *sz){
    struct stat st;
    if(stat(path,&st)!=0){dprintf(STDERR_FILENO,"rv: cannot stat: %s (%s)\n",path,strerror(errno));die("S");}
    if(st.st_size<0){dprintf(STDERR_FILENO,"rv: negative size: %s\n",path);die("L");}
    if((uint64_t)st.st_size>(100ULL*1024*1024*1024)){dprintf(STDERR_FILENO,"rv: too large (%lld): %s\n",(long long)st.st_size,path);die("L");}
    *sz=(size_t)st.st_size;
    FILE *f=fopen(path,"rb"); if(!f){dprintf(STDERR_FILENO,"rv: open: %s (%s)\n",path,strerror(errno));die("O");}
    uint8_t *b=malloc(*sz+1); if(!b){fclose(f);die("N");}
    if(*sz>0&&fread(b,1,*sz,f)!=*sz){dprintf(STDERR_FILENO,"rv: read: %s\n",path);fclose(f);free(b);die("R");}
    fclose(f); return b;
}

/* mmap-based fast read for worker threads */
static uint8_t *rfile_fast(const char *path,size_t *sz){
    /* open without following symlinks to avoid TOCTOU attacks */
    int fd=open(path,O_RDONLY|O_NOFOLLOW);
    if(fd<0){dprintf(STDERR_FILENO,"rv: open: %s (%s)\n",path,strerror(errno));die("O");}
    struct stat st; if(fstat(fd,&st)!=0){close(fd);die("S");}
    if(st.st_size<0||(uint64_t)st.st_size>(100ULL*1024*1024*1024)){close(fd);die("L");}
    *sz=(size_t)st.st_size;
    if(*sz==0){close(fd);uint8_t *b=malloc(1);if(!b)die("N");b[0]=0;return b;}
    void *m=mmap(NULL,*sz,PROT_READ,MAP_PRIVATE,fd,0); close(fd);
    if(m!=MAP_FAILED){
        madvise(m,*sz,MADV_SEQUENTIAL);
        uint8_t *b=malloc(*sz+1); if(!b){munmap(m,*sz);die("N");}
        memcpy(b,m,*sz); munmap(m,*sz); return b;
    }
    fd=open(path,O_RDONLY|O_NOFOLLOW); if(fd<0)die("O");
    uint8_t *b=malloc(*sz+1); if(!b){close(fd);die("N");}
    size_t done=0;
    while(done<*sz){ssize_t r=read(fd,b+done,*sz-done);if(r<=0){close(fd);free(b);die("R");}done+=(size_t)r;}
    close(fd); return b;
}

static void wfile(const char *path,const uint8_t *d,size_t s){
    char tmp[MAX_PATH_LEN];
    if(snprintf(tmp,sizeof(tmp),"%s.tmp",path)>=(int)sizeof(tmp))die("Q");
    FILE *f=fopen(tmp,"wb"); if(!f)die("W");
    size_t done=0;
    while(done<s){size_t r=fwrite(d+done,1,s-done,f);if(!r){fclose(f);unlink(tmp);die("V");}done+=r;}
    fclose(f);
    if(rename(tmp,path)!=0){unlink(tmp);die("X");}
}

/* ================================================================== */
/* Key derivation                                                       */
/* ================================================================== */
static void argon2(uint8_t key[32],const char *pw,const uint8_t *salt){
    STACK_CANARY_INIT(); STACK_CANARY_SAVE(); ANTIDIS_TRAP();
    if(crypto_pwhash(key,32,pw,strlen(pw),salt,
                     crypto_pwhash_OPSLIMIT_MODERATE,
                     crypto_pwhash_MEMLIMIT_MODERATE,
                     crypto_pwhash_ALG_ARGON2ID13)!=0) die("K");
    STACK_CANARY_CHECK();
}

static void derive_key(uint8_t key[32],const char *pw,const uint8_t *salt,
                        const uint8_t *mlkem_sk,const uint8_t *mlkem_ct){
    uint8_t ak[32]; argon2(ak,pw,salt);
    uint8_t ss[32]; memset(ss,0,32);
    if(mlkem_sk&&mlkem_ct) ml_kem1024_dec(ss,mlkem_ct,mlkem_sk);
    hybrid_kdf(key,32,ak,ss,salt,SALT_LEN);
    sodium_memzero(ak,32); sodium_memzero(ss,32); FAKE_CRYPTO_NOISE();
}

/* Fast KDF for randomly-generated OTC passwords (no Argon2id needed) */
static void fast_kdf(uint8_t key[OTC_KEY_LEN],const char *pw,const uint8_t salt[SALT_LEN]){
    keccak_ctx c; shake256_init(&c);
    shake256_absorb(&c,(const uint8_t*)pw,strlen(pw));
    uint8_t sep=0x01; shake256_absorb(&c,&sep,1);
    shake256_absorb(&c,salt,SALT_LEN);
    shake256_finalize(&c); shake256_squeeze(&c,key,OTC_KEY_LEN);
}

/* ================================================================== */
/* Public IP + US enforcement                                           */
/* ================================================================== */
/* ================================================================== */
/* HWID (Linux) — local sources only, no network call                  */
/* ================================================================== */
static void _hwid_append(uint8_t *buf,size_t *off,size_t cap,const char *lbl,const char *val){
    int n=snprintf((char*)buf+*off,cap-*off,"%s:%s\n",lbl,val?val:"?");
    if(n>0&&*off+(size_t)n<cap)*off+=(size_t)n;
}
static void _hwid_file(uint8_t *buf,size_t *off,size_t cap,const char *lbl,const char *path){
    FILE *f=fopen(path,"r"); char v[256]="?";
    if(f){if(!fgets(v,sizeof(v),f)){v[0]='?';v[1]='\0';}fclose(f);size_t vl=strlen(v);if(vl>0&&v[vl-1]=='\n')v[--vl]='\0';}
    _hwid_append(buf,off,cap,lbl,v);
}
static void _hwid_bytes(uint8_t *buf,size_t *off,size_t cap,const char *lbl,const uint8_t *d,size_t dl){
    int n=snprintf((char*)buf+*off,cap-*off,"%s:",lbl);if(n>0)*off+=(size_t)n;
    for(size_t i=0;i<dl&&*off+3<cap;i++){n=snprintf((char*)buf+*off,cap-*off,"%02x",d[i]);if(n>0)*off+=(size_t)n;}
    if(*off<cap)buf[(*off)++]='\n';
}

static void collect_hwid(uint8_t out[64],const uint8_t *user_sec){
    STACK_CANARY_INIT(); STACK_CANARY_SAVE(); RE_GUARD();
    uint8_t *buf=sa(HWID_BUF); size_t off=0;
    /* CPU vendor + model */
#if defined(__x86_64__) || defined(__i386__)
    { unsigned int a=0,b=0,c=0,d=0; __get_cpuid(0,&a,&b,&c,&d);
      char v[13]={0}; memcpy(v,&b,4); memcpy(v+4,&d,4); memcpy(v+8,&c,4);
      int n=snprintf((char*)buf+off,HWID_BUF-off,"cv:%s\n",v);if(n>0)off+=(size_t)n;
      __get_cpuid(1,&a,&b,&c,&d);
      n=snprintf((char*)buf+off,HWID_BUF-off,"smf:%08x\n",a);if(n>0)off+=(size_t)n; }
#endif
    { FILE *f=fopen("/proc/cpuinfo","r");
      if(f){char l[256];while(fgets(l,sizeof(l),f)){
        if(!strncmp(l,"model name",10)){char *v=strchr(l,':');if(v){v++;while(*v==' ')v++;
          size_t vl=strlen(v);if(vl>0&&v[vl-1]=='\n')v[--vl]='\0';
          int n=snprintf((char*)buf+off,HWID_BUF-off,"cpu:%s\n",v);if(n>0)off+=(size_t)n;break;}}
      fclose(f);}}}
    _hwid_file(buf,&off,HWID_BUF,"mid", "/etc/machine-id");
    _hwid_file(buf,&off,HWID_BUF,"puuid","/sys/class/dmi/id/product_uuid");
    _hwid_file(buf,&off,HWID_BUF,"bser", "/sys/class/dmi/id/board_serial");
    _hwid_file(buf,&off,HWID_BUF,"cser", "/sys/class/dmi/id/chassis_serial");
    _hwid_file(buf,&off,HWID_BUF,"pser", "/sys/class/dmi/id/product_serial");
    /* First stable MAC */
    { int found=0; DIR *nd=opendir("/sys/class/net");
      if(nd){struct dirent *ne;
        while((ne=readdir(nd))&&!found){
          if(!strcmp(ne->d_name,".")||!strcmp(ne->d_name,".."))continue;
          const char *sk[]={"lo","veth","docker","virbr","br-","tun","tap","bond","dummy","wwan","ppp",NULL};
          int bad=0; for(int i=0;sk[i];i++) if(!strncmp(ne->d_name,sk[i],strlen(sk[i]))){bad=1;break;}
          if(bad)continue;
          char mp[256]; snprintf(mp,sizeof(mp),"/sys/class/net/%s/address",ne->d_name);
          FILE *mf=fopen(mp,"r");if(!mf)continue;
          char mac[32]={0};
          if(fgets(mac,sizeof(mac),mf)&&strcmp(mac,"00:00:00:00:00:00\n")&&strcmp(mac,"00:00:00:00:00:00")){
            size_t ml=strlen(mac);if(ml>0&&mac[ml-1]=='\n')mac[--ml]='\0';
            int n=snprintf((char*)buf+off,HWID_BUF-off,"mac:%s\n",mac);if(n>0)off+=(size_t)n;found=1;}
          fclose(mf);}
        closedir(nd);}}
    /* No network call — HWID from local hardware only */
    _hwid_bytes(buf,&off,HWID_BUF,"us",user_sec,US_LEN);
    ANTIDIS_TRAP();
    sha3_512(out,buf,off); sf(buf,HWID_BUF);
    STACK_CANARY_CHECK();
}

/* ================================================================== */
/* OTC master password                                                  */
/* ================================================================== */
static void derive_otc_mpw(char *out,const uint8_t hwid[64],const uint8_t mlkem_ct[MLKEM1024_CT_BYTES]){
    ANTIDIS_TRAP2();
    uint8_t raw[32]; keccak_ctx c; shake256_init(&c);
    DECSTR(dom,"rv5-otc-mpw");
    shake256_absorb(&c,(uint8_t*)dom,strlen(dom)); sodium_memzero(dom,sizeof(dom));
    shake256_absorb(&c,hwid,64);
    shake256_absorb(&c,mlkem_ct,MLKEM1024_CT_BYTES);
    shake256_finalize(&c); shake256_squeeze(&c,raw,32);
    uint32_t tmp[8];
    for(int i=0;i<8;i++) tmp[i]=((uint32_t)raw[i*4]<<24)|((uint32_t)raw[i*4+1]<<16)|((uint32_t)raw[i*4+2]<<8)|(uint32_t)raw[i*4+3];
    char dig[OTC_MPW_LEN+1];
    for(int d=OTC_MPW_LEN-1;d>=0;d--){
        uint64_t rem=0;
        for(int i=0;i<8;i++){uint64_t cur=(rem<<32)|(uint64_t)tmp[i];tmp[i]=(uint32_t)(cur/62);rem=cur%62;}
        dig[d]=B62[rem];
    }
    dig[OTC_MPW_LEN]='\0'; memcpy(out,dig,OTC_MPW_LEN+1);
    sodium_memzero(raw,32); sodium_memzero(tmp,sizeof(tmp)); FAKE_CRYPTO_NOISE();
}

/* ================================================================== */
/* Manifest                                                             */
/* ================================================================== */
static void write_manifest(const char *cpath,uint32_t cnt,const uint8_t otc_hash[PQHASH_LEN],
                             const uint8_t enc_us[US_ENC_LEN],const uint8_t *enc_sk,
                             const uint8_t mlkem_ct[MLKEM1024_CT_BYTES]){
    char mp[MAX_PATH_LEN]; snprintf(mp,sizeof(mp),"%s.otc",cpath);
    uint8_t *buf=malloc(MANIFEST_LEN); if(!buf)die("N");
    uint8_t magic[4]; get_otcm(magic);
    size_t o=0;
    memcpy(buf+o,magic,4);o+=4; w32(buf+o,cnt);o+=4;
    memcpy(buf+o,otc_hash,PQHASH_LEN);o+=PQHASH_LEN;
    memcpy(buf+o,enc_us,US_ENC_LEN);o+=US_ENC_LEN;
    memcpy(buf+o,enc_sk,SK_ENC_LEN);o+=SK_ENC_LEN;
    memcpy(buf+o,mlkem_ct,MLKEM1024_CT_BYTES);
    wfile(mp,buf,MANIFEST_LEN); free(buf);
}
static void read_manifest(const char *cpath,uint32_t *cnt,uint8_t otc_hash[PQHASH_LEN],
                           uint8_t enc_us[US_ENC_LEN],uint8_t *enc_sk,
                           uint8_t mlkem_ct[MLKEM1024_CT_BYTES]){
    char mp[MAX_PATH_LEN]; snprintf(mp,sizeof(mp),"%s.otc",cpath);
    size_t sz; uint8_t *buf=rfile(mp,&sz);
    uint8_t magic[4]; get_otcm(magic);
    if(sz!=MANIFEST_LEN||memcmp(buf,magic,4)!=0){free(buf);die("Z");}
    size_t o=4;
    *cnt=r32(buf+o);o+=4;
    memcpy(otc_hash,buf+o,PQHASH_LEN);o+=PQHASH_LEN;
    memcpy(enc_us,buf+o,US_ENC_LEN);o+=US_ENC_LEN;
    memcpy(enc_sk,buf+o,SK_ENC_LEN);o+=SK_ENC_LEN;
    memcpy(mlkem_ct,buf+o,MLKEM1024_CT_BYTES);
    free(buf);
}

/* ================================================================== */
/* RV5C outer frame (Argon2id + ML-KEM + AES-256-GCM)                 */
/* ================================================================== */
#define HDR_SZ (MAGIC_LEN+1+8+SALT_LEN+NONCE_LEN)

static void write_rv5c(const char *path,const uint8_t *in,size_t il,const char *pw,
                        const uint8_t *otc,const uint8_t *mlkem_sk,const uint8_t *mlkem_ct){
    STACK_CANARY_INIT(); STACK_CANARY_SAVE(); ANTIDIS_TRAP();
    uint8_t salt[SALT_LEN],nonce[NONCE_LEN];
    randombytes_buf(salt,SALT_LEN); randombytes_buf(nonce,NONCE_LEN);
    uint8_t *key=sa(KEY_LEN); derive_key(key,pw,salt,mlkem_sk,mlkem_ct);
    if(otc) for(size_t i=0;i<OTC_LEN&&i<KEY_LEN;i++) key[i]^=otc[i];
    uint8_t mkey[MAC_LEN]; {uint8_t ctx[]={'m','a','c',0};shake256_mac(mkey,MAC_LEN,key,KEY_LEN,ctx,4);}
    uint8_t *ct=malloc(il+TAG_LEN); if(!ct){sf(key,KEY_LEN);die("C");}
    unsigned long long cl;
    if(crypto_aead_aes256gcm_encrypt(ct,&cl,in,il,NULL,0,NULL,nonce,key)!=0){sf(key,KEY_LEN);free(ct);die("A");}
    sf(key,KEY_LEN);
    uint8_t hdr[HDR_SZ]; size_t ho=0;
    uint8_t magic[8]; get_magic(magic);
    memcpy(hdr+ho,magic,MAGIC_LEN);ho+=MAGIC_LEN; hdr[ho++]=VERSION;
    w64(hdr+ho,(uint64_t)il);ho+=8;
    memcpy(hdr+ho,salt,SALT_LEN);ho+=SALT_LEN; memcpy(hdr+ho,nonce,NONCE_LEN);ho+=NONCE_LEN;
    uint8_t mac[MAC_LEN];
    {keccak_ctx mc;shake256_init(&mc);shake256_absorb(&mc,mkey,MAC_LEN);shake256_absorb(&mc,hdr,ho);shake256_absorb(&mc,ct,(size_t)cl);shake256_finalize(&mc);shake256_squeeze(&mc,mac,MAC_LEN);}
    FILE *f=fopen(path,"wb"); if(!f){free(ct);die("F");}
    fwrite(hdr,1,ho,f); fwrite(ct,1,(size_t)cl,f); fwrite(mac,1,MAC_LEN,f);
    fclose(f); free(ct); STACK_CANARY_CHECK();
}

static uint8_t *read_rv5c(const char *path,const char *pw,const uint8_t *otc,
                            const uint8_t *mlkem_sk,const uint8_t *mlkem_ct_m,size_t *ol){
    STACK_CANARY_INIT(); STACK_CANARY_SAVE(); ANTIDIS_TRAP();
    size_t sz; uint8_t *buf=rfile(path,&sz);
    if(sz<HDR_SZ+TAG_LEN+MAC_LEN){free(buf);die("H");}
    uint8_t magic[8]; get_magic(magic);
    if(memcmp(buf,magic,MAGIC_LEN)!=0){free(buf);die("M");}
    size_t o=MAGIC_LEN;
    if(buf[o++]!=VERSION){free(buf);die("V");}
    o+=8;
    uint8_t salt[SALT_LEN],nonce[NONCE_LEN];
    memcpy(salt,buf+o,SALT_LEN);o+=SALT_LEN; memcpy(nonce,buf+o,NONCE_LEN);o+=NONCE_LEN;
    size_t hl=o,cl=sz-hl-MAC_LEN; if(cl<TAG_LEN){free(buf);die("U");}
    const uint8_t *ct=buf+hl,*mac=buf+sz-MAC_LEN;
    uint8_t *key=sa(KEY_LEN); derive_key(key,pw,salt,mlkem_sk,mlkem_ct_m);
    if(otc) for(size_t i=0;i<OTC_LEN&&i<KEY_LEN;i++) key[i]^=otc[i];
    uint8_t mkey[MAC_LEN]; {uint8_t ctx[]={'m','a','c',0};shake256_mac(mkey,MAC_LEN,key,KEY_LEN,ctx,4);}
    uint8_t emac[MAC_LEN];
    {keccak_ctx mc;shake256_init(&mc);shake256_absorb(&mc,mkey,MAC_LEN);shake256_absorb(&mc,buf,hl);shake256_absorb(&mc,ct,cl);shake256_finalize(&mc);shake256_squeeze(&mc,emac,MAC_LEN);}
    if(sodium_memcmp(mac,emac,MAC_LEN)!=0){sf(key,KEY_LEN);free(buf);die("J");}
    uint8_t *plain=malloc(cl-TAG_LEN+1); if(!plain){sf(key,KEY_LEN);free(buf);die("N");}
    unsigned long long dl;
    if(crypto_aead_aes256gcm_decrypt(plain,&dl,NULL,ct,cl,NULL,0,nonce,key)!=0){sf(key,KEY_LEN);free(buf);free(plain);die("Y");}
    sf(key,KEY_LEN); free(buf); *ol=(size_t)dl;
    STACK_CANARY_CHECK(); return plain;
}

/* ================================================================== */
/* Password generation                                                  */
/* ================================================================== */
static void gen_password(char out[FILE_PW_LEN+1]){
    uint8_t raw[64]; int pos=0;
    while(pos<FILE_PW_LEN){
        randombytes_buf(raw,sizeof(raw));
        for(int i=0;i<(int)sizeof(raw)&&pos<FILE_PW_LEN;i++)
            if(raw[i]<248) out[pos++]=B62[raw[i]%62];
    }
    out[FILE_PW_LEN]='\0'; sodium_memzero(raw,sizeof(raw));
}

/* ================================================================== */
/* Growable buffer                                                      */
/* ================================================================== */
typedef struct{uint8_t *d;size_t sz,cap;}BB;
static void bb_init(BB *b){b->cap=64*1024;b->sz=0;b->d=malloc(b->cap);if(!b->d)die("B");}
static void bb_need(BB *b,size_t x){while(b->sz+x>b->cap){b->cap*=2;uint8_t*nb=realloc(b->d,b->cap);if(!nb)die("B");b->d=nb;}}
static void bb_app(BB *b,const void *s,size_t l){bb_need(b,l);memcpy(b->d+b->sz,s,l);b->sz+=l;}
static void bb_free(BB *b){free(b->d);b->d=NULL;b->sz=b->cap=0;}

/* ================================================================== */
/* Key file                                                             */
/* ================================================================== */
typedef struct{char label[MAX_PATH_LEN];char pw[FILE_PW_LEN+1];}KeyEntry;
typedef struct{KeyEntry *entries;size_t cnt,cap;}KeyFile;

static void kf_init(KeyFile *kf){kf->cap=64;kf->cnt=0;kf->entries=malloc(kf->cap*sizeof(KeyEntry));if(!kf->entries)die("N");}
static void kf_add(KeyFile *kf,const char *label,const char *pw){
    if(kf->cnt>=kf->cap){kf->cap*=2;kf->entries=realloc(kf->entries,kf->cap*sizeof(KeyEntry));if(!kf->entries)die("N");}
    strncpy(kf->entries[kf->cnt].label,label,MAX_PATH_LEN-1);kf->entries[kf->cnt].label[MAX_PATH_LEN-1]='\0';
    strncpy(kf->entries[kf->cnt].pw,pw,FILE_PW_LEN);kf->entries[kf->cnt].pw[FILE_PW_LEN]='\0';
    kf->cnt++;
}
static const char *kf_get(const KeyFile *kf,const char *label){
    for(size_t i=0;i<kf->cnt;i++) if(!strcmp(kf->entries[i].label,label)) return kf->entries[i].pw;
    return NULL;
}
/* ================================================================== */
/* Key file — plaintext label:password format                          */
/* ================================================================== */
static void kf_write(const KeyFile *kf,const char *path){
    FILE *f=fopen(path,"w"); if(!f)die("W");
    for(size_t i=0;i<kf->cnt;i++) fprintf(f,"%s:%s\n",kf->entries[i].label,kf->entries[i].pw);
    fclose(f);
}
static void kf_read(KeyFile *kf,const char *path){
    kf_init(kf); FILE *f=fopen(path,"r"); if(!f)die("O");
    char line[MAX_PATH_LEN+FILE_PW_LEN+4];
    while(fgets(line,sizeof(line),f)){
        size_t ll=strlen(line); if(ll>0&&line[ll-1]=='\n')line[--ll]='\0'; if(!ll)continue;
        char *lc=strrchr(line,':'); if(!lc)continue; *lc='\0'; kf_add(kf,line,lc+1);
    }
    fclose(f);
}
static void kf_free(KeyFile *kf){
    if(kf->entries){for(size_t i=0;i<kf->cnt;i++)sodium_memzero(kf->entries[i].pw,FILE_PW_LEN);free(kf->entries);}
    kf->entries=NULL;kf->cnt=kf->cap=0;
}

/* ================================================================== */
/* OTC encrypt / decrypt (XChaCha20-Poly1305 + SHAKE-256 KDF)         */
/* ================================================================== */
static uint8_t *otc_encrypt(const uint8_t *in,size_t il,const char *pw,size_t *ol){
    uint8_t salt[SALT_LEN],nonce[OTC_NONCE_LEN];
    randombytes_buf(salt,SALT_LEN); randombytes_buf(nonce,OTC_NONCE_LEN);
    uint8_t key[OTC_KEY_LEN]; fast_kdf(key,pw,salt);
    size_t olen=SALT_LEN+OTC_NONCE_LEN+il+OTC_TAG_LEN;
    uint8_t *out=malloc(olen); if(!out)die("N");
    memcpy(out,salt,SALT_LEN); memcpy(out+SALT_LEN,nonce,OTC_NONCE_LEN);
    unsigned long long cl;
    if(crypto_aead_xchacha20poly1305_ietf_encrypt(out+SALT_LEN+OTC_NONCE_LEN,&cl,in,il,NULL,0,NULL,nonce,key)!=0)
        {sodium_memzero(key,sizeof(key));free(out);die("A");}
    sodium_memzero(key,sizeof(key));
    *ol=SALT_LEN+OTC_NONCE_LEN+(size_t)cl;
    return out;
}
static uint8_t *otc_decrypt(const uint8_t *in,size_t il,const char *pw,size_t *ol){
    if(il<SALT_LEN+OTC_NONCE_LEN+OTC_TAG_LEN)die("H");
    uint8_t salt[SALT_LEN],nonce[OTC_NONCE_LEN];
    memcpy(salt,in,SALT_LEN); memcpy(nonce,in+SALT_LEN,OTC_NONCE_LEN);
    uint8_t key[OTC_KEY_LEN]; fast_kdf(key,pw,salt);
    size_t ctl=il-SALT_LEN-OTC_NONCE_LEN;
    uint8_t *out=malloc(ctl); if(!out){sodium_memzero(key,sizeof(key));die("N");}
    unsigned long long dl;
    if(crypto_aead_xchacha20poly1305_ietf_decrypt(out,&dl,NULL,in+SALT_LEN+OTC_NONCE_LEN,ctl,NULL,0,nonce,key)!=0)
        {sodium_memzero(key,sizeof(key));free(out);die("Y: wrong password or corrupt data");}
    sodium_memzero(key,sizeof(key)); *ol=(size_t)dl; return out;
}

/* ================================================================== */
/* File list                                                            */
/* ================================================================== */
typedef struct{char **paths;size_t cnt,cap;}FileList;
static void fl_init(FileList *fl){fl->cap=64;fl->cnt=0;fl->paths=malloc(fl->cap*sizeof(char*));if(!fl->paths)die("N");}
static void fl_add(FileList *fl,const char *p){
    if(fl->cnt>=fl->cap){fl->cap*=2;fl->paths=realloc(fl->paths,fl->cap*sizeof(char*));if(!fl->paths)die("N");}
    fl->paths[fl->cnt++]=strdup(p);
}
static void fl_free(FileList *fl){for(size_t i=0;i<fl->cnt;i++)free(fl->paths[i]);free(fl->paths);fl->paths=NULL;fl->cnt=fl->cap=0;}
static void fl_collect(FileList *fl,const char *abs_dir,const char *rel_prefix){
    DIR *d=opendir(abs_dir); if(!d)return;
    struct dirent *e;
    while((e=readdir(d))!=NULL){
        if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
        char abs[MAX_PATH_LEN],rel[MAX_PATH_LEN];
        if(snprintf(abs,sizeof(abs),"%s/%s",abs_dir,e->d_name)>=(int)sizeof(abs))continue;
        if(*rel_prefix) snprintf(rel,sizeof(rel),"%s/%s",rel_prefix,e->d_name);
        else            snprintf(rel,sizeof(rel),"%s",e->d_name);
        struct stat st; if(lstat(abs,&st)!=0)continue;
        if     (S_ISREG(st.st_mode))fl_add(fl,rel);
        else if(S_ISDIR(st.st_mode))fl_collect(fl,abs,rel);
    }
    closedir(d);
}

/* ================================================================== */
/* Container wire format                                                */
/*  [magic 8][file_count 4]                                            */
/*  per file: [relpath_len 2][relpath N][data_len 8][enc_data M]       */
/*  Whole blob wrapped by otc_encrypt(container_pw)                   */
/* ================================================================== */
static const uint8_t CONT_MAGIC[8]={'R','V','C','O','N','T',0x05,0x00};

/* validate a relative path extracted from a container blob or filesystem
 * walk.  Reject absolute names, any “..” segments, and empty strings.  This
 * is deliberately conservative – a legitimate filename containing “..” will
 * be skipped rather than causing a safety breach. */
static int valid_relpath(const char *rel){
    if(!rel || rel[0]=='\0' || rel[0]=='/') return 0;
    /* reject parent‑directory references anywhere in the string */
    if(strstr(rel,"..")) return 0;
    return 1;
}

/* ================================================================== */
/* Portable semaphore (mutex + condvar)                                 */
/* ================================================================== */
typedef struct{pthread_mutex_t mu;pthread_cond_t cv;int val;}Sem;
static void sem_setup(Sem *s,int v){pthread_mutex_init(&s->mu,NULL);pthread_cond_init(&s->cv,NULL);s->val=v;}
static void sem_wait_s(Sem *s){pthread_mutex_lock(&s->mu);while(s->val<=0)pthread_cond_wait(&s->cv,&s->mu);s->val--;pthread_mutex_unlock(&s->mu);}
static void sem_post_s(Sem *s){pthread_mutex_lock(&s->mu);s->val++;pthread_cond_signal(&s->cv);pthread_mutex_unlock(&s->mu);}
static void sem_destroy_s(Sem *s){pthread_mutex_destroy(&s->mu);pthread_cond_destroy(&s->cv);}

/* ================================================================== */
/* CPU count                                                            */
/* ================================================================== */
static int cpu_count(void){long n=sysconf(_SC_NPROCESSORS_ONLN);return(n>1)?(int)n:1;}

/* ================================================================== */
/* Global flag for swap failsafe                                        */
/* ================================================================== */
static int g_ignore_swap_failsafe = 0;
static int g_allow_vm = 0;
static int g_no_compress = 0;

/* ================================================================== */
/* Memory/Swap Monitoring Failsafe                                     */
/* ================================================================== */
/* ================================================================== */
/* Password strength estimator                                          */
/* ================================================================== */
static double pw_entropy_bits(const char *pw){
    size_t len=strlen(pw); if(len==0)return 0.0;
    int has_lower=0,has_upper=0,has_digit=0,has_sym=0;
    for(size_t i=0;i<len;i++){
        unsigned char c=(unsigned char)pw[i];
        if(c>='a'&&c<='z')has_lower=1;
        else if(c>='A'&&c<='Z')has_upper=1;
        else if(c>='0'&&c<='9')has_digit=1;
        else if(c>=0x20&&c<=0x7E)has_sym=1;
    }
    double pool=0;
    if(has_lower)pool+=26; if(has_upper)pool+=26;
    if(has_digit)pool+=10; if(has_sym)pool+=32;
    if(pool<2)pool=2;
    double bits=(double)len*(log(pool)/log(2.0));
    /* penalty: >40% repeated chars */
    { int rep=0; for(size_t i=1;i<len;i++) if(pw[i]==pw[i-1])rep++;
      if(len>1&&(double)rep/(double)(len-1)>0.4)bits*=0.7; }
    /* penalty: keyboard walk */
    { int walk=0,wlen=1;
      for(size_t i=1;i<len;i++){
          int d=(int)(unsigned char)pw[i]-(int)(unsigned char)pw[i-1];
          if(d==1||d==-1){wlen++;if(wlen>=3){walk=1;break;}}else wlen=1;
      }
      if(walk)bits*=0.75; }
    return bits;
}
static void pw_strength_check(const char *pw, int allow_weak){
    double bits=pw_entropy_bits(pw);
    const char *label;
    if(bits<28)label="very weak";
    else if(bits<40)label="weak";
    else if(bits<60)label="moderate";
    else if(bits<80)label="strong";
    else label="very strong";
    printf("  Password strength: %.0f bits — %s\n",bits,label);
    if(bits<40.0&&!allow_weak){
        fprintf(stderr,"rv: password too weak (%.0f bits, min 40). Use --weak-pw to override.\n",bits);
        _exit(1);
    }
    if(bits<60.0&&bits>=40.0)
        printf("  Tip: use a passphrase of 4+ random words for better security.\n");
}

/* ================================================================== */
/* Persistent on-disk fail counter                                     */
/*                                                                      */
/* Stored as a plain integer in <base>.fails next to the .otc file.   */
/* Incremented before each decode attempt, reset on success.           */
/* At WIPE_FAIL_LIMIT the .otc is overwritten with random bytes and   */
/* deleted — the counter persists across process restarts.             */
/* ================================================================== */
#define WIPE_FAIL_LIMIT 5

static char g_fail_path[MAX_PATH_LEN] = {0};

static int fail_count_read(void){
    if(!g_fail_path[0]) return 0;
    FILE *f=fopen(g_fail_path,"r"); if(!f) return 0;
    int n=0; fscanf(f,"%d",&n); fclose(f); return n;
}
static void fail_count_write(int n){
    if(!g_fail_path[0]) return;
    FILE *f=fopen(g_fail_path,"w"); if(!f) return;
    fprintf(f,"%d\n",n); fclose(f);
}
static void fail_count_reset(void){
    if(g_fail_path[0]) unlink(g_fail_path);
}
static void fail_count_hit(const char *cont_path){
    int n = fail_count_read() + 1;
    fail_count_write(n);
    dprintf(STDERR_FILENO,"rv: wrong password (%d/%d)\n",n,WIPE_FAIL_LIMIT);
    if(n >= WIPE_FAIL_LIMIT && cont_path){
        dprintf(STDERR_FILENO,"rv: too many failures — destroying %s\n",cont_path);
        int fd=open(cont_path,O_WRONLY);
        if(fd>=0){
            struct stat st; fstat(fd,&st);
            size_t sz=(size_t)st.st_size;
            uint8_t *rnd=malloc(4096); if(rnd){
                size_t done=0;
                while(done<sz){
                    randombytes_buf(rnd,4096);
                    size_t chunk=sz-done>4096?4096:sz-done;
                    write(fd,rnd,chunk); done+=chunk;
                }
                free(rnd);
            }
            close(fd);
        }
        unlink(cont_path);
        fail_count_reset();
        _exit(1);
    }
}

/* ================================================================== */
/* verify: check container integrity without decoding to disk          */
/* ================================================================== */
static void verify_otc(const char *cont_path, const char *key_path){
    printf("Verifying: %s\n", cont_path);
    KeyFile kf; kf_read(&kf, key_path);

    size_t root_enc_sz; uint8_t *root_enc=rfile(cont_path,&root_enc_sz);
    const char *root_pw=kf_get(&kf,"root");
    if(!root_pw){free(root_enc);kf_free(&kf);die("Z: no root password in key file");}

    size_t root_sz; uint8_t *root_data=otc_decrypt(root_enc,root_enc_sz,root_pw,&root_sz);
    free(root_enc);
    if(root_sz<12||memcmp(root_data,CONT_MAGIC,8)!=0){free(root_data);kf_free(&kf);die("M: bad root magic");}

    uint32_t nconts=r32(root_data+8); size_t off=12;
    printf("Containers: %u\n", nconts);
    size_t total_files=0; int errors=0;

    for(uint32_t ci=0;ci<nconts;ci++){
        if(off+2>root_sz)break;
        uint16_t cnl=r16(root_data+off);off+=2;
        if(off+cnl>root_sz)break;
        char cname[MAX_PATH_LEN]; memcpy(cname,root_data+off,cnl);cname[cnl]='\0';off+=cnl;
        if(off+8>root_sz)break;
        uint64_t esz=r64(root_data+off);off+=8;
        if(off+esz>root_sz)break;

        char lbl[MAX_PATH_LEN]; snprintf(lbl,sizeof(lbl),"cont:%s",cname);
        const char *cpw=kf_get(&kf,lbl);
        if(!cpw){dprintf(STDERR_FILENO,"  MISSING key for %s\n",cname);errors++;off+=(size_t)esz;continue;}

        size_t wire_sz; uint8_t *wire=otc_decrypt(root_data+off,(size_t)esz,cpw,&wire_sz);
        off+=(size_t)esz;
        if(!wire||wire_sz<12||memcmp(wire,CONT_MAGIC,8)!=0){
            dprintf(STDERR_FILENO,"  CORRUPT container %s\n",cname); errors++;
            if(wire)free(wire); continue;
        }
        uint32_t nfiles=r32(wire+8); size_t woff=12;
        char cl[MAX_PATH_LEN]; strncpy(cl,cname,sizeof(cl)-1);cl[sizeof(cl)-1]='\0';
        char *dp=strstr(cl,".cont");if(dp)*dp='\0';

        for(uint32_t fi=0;fi<nfiles;fi++){
            if(woff+2>wire_sz)break;
            uint16_t rplen=r16(wire+woff);woff+=2;
            if(woff+rplen>wire_sz)break;
            char relpath[MAX_PATH_LEN]; memcpy(relpath,wire+woff,rplen);relpath[rplen]='\0';woff+=rplen;
            if(woff+8>wire_sz)break;
            uint64_t fesz=r64(wire+woff);woff+=8;
            if(woff+fesz>wire_sz)break;
            snprintf(lbl,sizeof(lbl),"file:%s/%s",cl,relpath);
            const char *fpw=kf_get(&kf,lbl);
            if(!fpw){dprintf(STDERR_FILENO,"  MISSING key for %s\n",relpath);errors++;woff+=(size_t)fesz;continue;}
            /* Attempt decrypt to verify tag — don't keep plaintext */
            size_t psz; uint8_t *plain=otc_decrypt(wire+woff,(size_t)fesz,fpw,&psz);
            if(!plain){dprintf(STDERR_FILENO,"  CORRUPT file %s\n",relpath);errors++;}
            else{sodium_memzero(plain,psz);free(plain);total_files++;}
            woff+=(size_t)fesz;
        }
        sodium_memzero(wire,wire_sz); free(wire);
    }
    sodium_memzero(root_data,root_sz); free(root_data); kf_free(&kf);
    if(errors==0)
        printf("OK — %u container(s), %zu file(s) verified, no errors.\n",nconts,total_files);
    else
        printf("FAILED — %d error(s) found.\n",errors);
}

static void check_swap_usage(void) {
    if (g_ignore_swap_failsafe) return;
    
#ifdef __linux__
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return;
    
    uint64_t mem_total = 0, mem_free = 0, swap_total = 0, swap_free = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemTotal: %lu", &mem_total) == 1) continue;
        if (sscanf(line, "MemFree: %lu", &mem_free) == 1) continue;
        if (sscanf(line, "SwapTotal: %lu", &swap_total) == 1) continue;
        if (sscanf(line, "SwapFree: %lu", &swap_free) == 1) continue;
    }
    fclose(f);
    
    if (swap_total > 0 && swap_free < swap_total) {
        /* System is using swap - kill process */
        dprintf(STDERR_FILENO, "![RAN OUT OF RAM]!\n");
        _exit(1);
    }
#endif
}

/* ================================================================== */
/* Encode worker                                                        */
/* ================================================================== */
typedef struct{
    const char     *root_dir;
    char          **relpaths;
    size_t          nfiles;
    char            cont_name[MAX_PATH_LEN];
    KeyFile        *kf;
    pthread_mutex_t *kf_mutex;
    Sem            *slot;
    uint8_t        *enc_data;
    size_t          enc_sz;
    char            cont_pw[CONT_PW_LEN+1];
    int             done;
}ContWork;

static void *cont_worker(void *arg){
    ContWork *w=(ContWork*)arg;
    check_swap_usage();
    gen_password(w->cont_pw);
    /* validate relative paths supplied by the collector; we treat any bad
       name as an error rather than trying to encode it. */
    for(size_t i=0;i<w->nfiles;i++){
        if(!valid_relpath(w->relpaths[i])){
            dprintf(STDERR_FILENO,"rv: invalid path in container: %s\n",w->relpaths[i]);
            die("P");
        }
    }

    /* Pre-size wire buffer */
    size_t hint=12;
    for(size_t i=0;i<w->nfiles;i++){
        char abs[MAX_PATH_LEN]; snprintf(abs,sizeof(abs),"%s/%s",w->root_dir,w->relpaths[i]);
        /* open file with NOFOLLOW to get size without risk of symlink attack */
        struct stat st;
        int fd=open(abs,O_RDONLY|O_NOFOLLOW);
        if(fd>=0){
            if(fstat(fd,&st)==0 && st.st_size>0)
                hint+=2+strlen(w->relpaths[i])+8+(size_t)st.st_size+SALT_LEN+OTC_NONCE_LEN+OTC_TAG_LEN+64;
            else
                hint+=256;
            close(fd);
        } else {
            hint+=256;
        }
    }
    BB wire; wire.cap=hint;wire.sz=0;wire.d=malloc(wire.cap);if(!wire.d)die("N");
    bb_app(&wire,CONT_MAGIC,8);
    uint8_t fc[4]; w32(fc,(uint32_t)w->nfiles); bb_app(&wire,fc,4);
    /* Allocate file passwords in locked memory so they cannot be swapped */
    size_t fpws_sz = w->nfiles * (FILE_PW_LEN+1);
    char (*fpws)[FILE_PW_LEN+1] = (char(*)[FILE_PW_LEN+1])plat_secure_alloc(fpws_sz);
    if(!fpws)die("N");
    wipe_register((volatile uint8_t*)fpws, fpws_sz);
    for(size_t i=0;i<w->nfiles;i++){
        gen_password(fpws[i]);
        char abs[MAX_PATH_LEN]; snprintf(abs,sizeof(abs),"%s/%s",w->root_dir,w->relpaths[i]);
        size_t fsz; uint8_t *fdata=rfile_fast(abs,&fsz);
        size_t efsz; uint8_t *ef=otc_encrypt(fdata,fsz,fpws[i],&efsz);
        sodium_memzero(fdata,fsz); free(fdata);
        size_t rplen=strlen(w->relpaths[i]);
        uint8_t rpl[2]; w16(rpl,(uint16_t)rplen); bb_app(&wire,rpl,2);
        bb_app(&wire,w->relpaths[i],rplen);
        uint8_t dl[8]; w64(dl,(uint64_t)efsz); bb_app(&wire,dl,8);
        bb_app(&wire,ef,efsz); free(ef);
    }
    w->enc_data=otc_encrypt(wire.d,wire.sz,w->cont_pw,&w->enc_sz);
    sodium_memzero(wire.d,wire.sz); bb_free(&wire);
    /* Lock kf briefly to register passwords */
    char cl[MAX_PATH_LEN]; strncpy(cl,w->cont_name,sizeof(cl)-1);cl[sizeof(cl)-1]='\0';
    char *dp=strstr(cl,".cont"); if(dp)*dp='\0';
    pthread_mutex_lock(w->kf_mutex);
    char lbl[MAX_PATH_LEN];
    snprintf(lbl,sizeof(lbl),"cont:%s",w->cont_name); kf_add(w->kf,lbl,w->cont_pw);
    for(size_t i=0;i<w->nfiles;i++){
        snprintf(lbl,sizeof(lbl),"file:%s/%s",cl,w->relpaths[i]);
        kf_add(w->kf,lbl,fpws[i]); sodium_memzero(fpws[i],FILE_PW_LEN);
    }
    pthread_mutex_unlock(w->kf_mutex);
    wipe_unregister((volatile uint8_t*)fpws);
    plat_secure_free((uint8_t*)fpws, fpws_sz);
    w->done=1; sem_post_s(w->slot);
    return NULL;
}

/* ================================================================== */
/* Encode: folder (or single file) → <base>_root.otc + <base>.key     */
/* ================================================================== */
static void encode_otc(const char *folder,int remove_original,int ignore_swap){
    g_ignore_swap_failsafe = ignore_swap;
    char root[MAX_PATH_LEN]; strncpy(root,folder,sizeof(root)-1);root[sizeof(root)-1]='\0';
    size_t rl=strlen(root); while(rl>1&&root[rl-1]=='/')root[--rl]='\0';
    const char *base=strrchr(root,'/'); base=base?base+1:root;

    FileList fl; fl_init(&fl); fl_collect(&fl,root,"");
    if(fl.cnt==0){fl_free(&fl);fprintf(stderr,"rv: no files in %s\n",root);return;}
    if(fl.cnt > 10000000){fl_free(&fl);die("too many files");}

    size_t nconts=(fl.cnt+(size_t)g_files_per_cont-1)/(size_t)g_files_per_cont;
    int ncpus=cpu_count();
    int slots=ncpus*2; if(slots<2)slots=2;
    printf("Encoding %zu file(s) → %zu container(s)  [%d CPUs, %d concurrent]\n",fl.cnt,nconts,ncpus,slots);
    printf("  --files-per-container: %d\n", g_files_per_cont);

    KeyFile kf; kf_init(&kf);
    pthread_mutex_t kf_mutex=PTHREAD_MUTEX_INITIALIZER;
    char root_pw[ROOT_PW_LEN+1]; gen_password(root_pw); kf_add(&kf,"root",root_pw);

    Sem slot_sem; sem_setup(&slot_sem,slots);
    ContWork *work=calloc(nconts,sizeof(ContWork));
    pthread_t *tids=malloc(nconts*sizeof(pthread_t));
    if(!work||!tids)die("N");

    for(size_t ci=0;ci<nconts;ci++){
        size_t fs=ci*(size_t)g_files_per_cont, fe=fs+(size_t)g_files_per_cont; if(fe>fl.cnt)fe=fl.cnt;
        snprintf(work[ci].cont_name,MAX_PATH_LEN,"%s_%zu.cont",base,ci+1);
        work[ci].root_dir=root; work[ci].relpaths=fl.paths+fs; work[ci].nfiles=fe-fs;
        work[ci].kf=&kf; work[ci].kf_mutex=&kf_mutex; work[ci].slot=&slot_sem;
        work[ci].enc_data=NULL; work[ci].enc_sz=0; work[ci].done=0;
        sem_wait_s(&slot_sem);
        pthread_create(&tids[ci],NULL,cont_worker,&work[ci]);
    }
    for(size_t ci=0;ci<nconts;ci++){
        check_swap_usage();
        pthread_join(tids[ci],NULL);
        printf("\r  [Encoding] "); draw_progress(ci+1,nconts); printf("  %zu/%zu containers\n",ci+1,nconts);
    }
    sem_destroy_s(&slot_sem); pthread_mutex_destroy(&kf_mutex);

    /* Pre-size root archive */
    size_t ra_hint=12;
    for(size_t ci=0;ci<nconts;ci++) ra_hint+=2+strlen(work[ci].cont_name)+8+work[ci].enc_sz;
    BB ra; ra.cap=ra_hint;ra.sz=0;ra.d=malloc(ra.cap);if(!ra.d)die("N");
    bb_app(&ra,CONT_MAGIC,8);
    uint8_t nc_b[4]; w32(nc_b,(uint32_t)nconts); bb_app(&ra,nc_b,4);
    for(size_t ci=0;ci<nconts;ci++){
        size_t cnl=strlen(work[ci].cont_name);
        uint8_t cnl_b[2]; w16(cnl_b,(uint16_t)cnl); bb_app(&ra,cnl_b,2);
        bb_app(&ra,work[ci].cont_name,cnl);
        uint8_t esz_b[8]; w64(esz_b,(uint64_t)work[ci].enc_sz); bb_app(&ra,esz_b,8);
        bb_app(&ra,work[ci].enc_data,work[ci].enc_sz);
        free(work[ci].enc_data);
    }
    free(work); free(tids);

    printf("Encrypting root archive (%zu bytes)...\n",ra.sz);
    check_swap_usage();
    size_t root_enc_sz; uint8_t *root_enc=otc_encrypt(ra.d,ra.sz,root_pw,&root_enc_sz);
    sodium_memzero(ra.d,ra.sz); bb_free(&ra); sodium_memzero(root_pw,ROOT_PW_LEN);

    char opath[MAX_PATH_LEN],key_path[MAX_PATH_LEN];
    snprintf(opath,sizeof(opath),"%s_root.otc",base);
    snprintf(key_path,sizeof(key_path),"%s.key",base);
    wfile(opath,root_enc,root_enc_sz); free(root_enc);
    kf_write(&kf,key_path); kf_free(&kf); fl_free(&fl);

    printf("Created: %s\n",opath);
    printf("Created: %s\n",key_path);
    printf("Keep %s safe — it is the only way to decode.\n",key_path);

    if(remove_original){
        printf("Securely wiping source files...\n");
        for(size_t i=0;i<fl.cnt;i++){
            char abs[MAX_PATH_LEN]; snprintf(abs,sizeof(abs),"%s/%s",root,fl.paths[i]);
            /* 3-pass overwrite: random → zero → random */
            struct stat st; if(stat(abs,&st)!=0){unlink(abs);continue;}
            size_t fsz=(size_t)st.st_size;
            int fd=open(abs,O_WRONLY); if(fd>=0&&fsz>0){
                uint8_t *buf=malloc(65536); if(buf){
                    for(int pass=0;pass<3;pass++){
                        lseek(fd,0,SEEK_SET);
                        size_t done=0;
                        while(done<fsz){
                            size_t chunk=fsz-done; if(chunk>65536)chunk=65536;
                            if(pass==1) memset(buf,0,chunk);
                            else randombytes_buf(buf,chunk);
                            write(fd,buf,chunk); done+=chunk;
                        }
                        fsync(fd);
                    }
                    free(buf);
                }
                close(fd);
            } else if(fd>=0) close(fd);
            unlink(abs);
        }
        if(rmdir(root)!=0)
            dprintf(STDERR_FILENO,"rv: warning: could not rmdir %s\n",root);
        else
            printf("Securely removed: %s/\n",root);
    }
}

/* ================================================================== */
/* Decode worker                                                        */
/* ================================================================== */
typedef struct{
    const uint8_t  *enc;
    size_t          enc_sz;
    char            cont_name[MAX_PATH_LEN];
    const char     *out_dir;
    const KeyFile  *kf;
    Sem            *slot;
}DecWork;

static void *dec_worker(void *arg){
    DecWork *w=(DecWork*)arg;
    check_swap_usage();
    char lbl[MAX_PATH_LEN]; snprintf(lbl,sizeof(lbl),"cont:%s",w->cont_name);
    const char *cont_pw=kf_get(w->kf,lbl);
    if(!cont_pw){sem_post_s(w->slot);die("Z: missing container password");}
    size_t wire_sz; uint8_t *wire=otc_decrypt(w->enc,w->enc_sz,cont_pw,&wire_sz);
    if(wire_sz<12||memcmp(wire,CONT_MAGIC,8)!=0){free(wire);sem_post_s(w->slot);die("M: bad container magic");}
    uint32_t nfiles=r32(wire+8); size_t woff=12;
    char cl[MAX_PATH_LEN]; strncpy(cl,w->cont_name,sizeof(cl)-1);cl[sizeof(cl)-1]='\0';
    char *dp=strstr(cl,".cont"); if(dp)*dp='\0';
    for(uint32_t fi=0;fi<nfiles;fi++){
        if(woff+2>wire_sz)break;
        uint16_t rplen=r16(wire+woff);woff+=2;
        if(woff+rplen>wire_sz)break;
        char relpath[MAX_PATH_LEN]; memcpy(relpath,wire+woff,rplen);relpath[rplen]='\0';woff+=rplen;
        /* validate the relpath to prevent directory escape */
        if(!valid_relpath(relpath)){
            free(wire); sem_post_s(w->slot);
            dprintf(STDERR_FILENO,"rv: bad relative path in container: %s\n",relpath);
            die("P");
        }
        if(woff+8>wire_sz)break;
        uint64_t fesz=r64(wire+woff);woff+=8;
        if(woff+fesz>wire_sz)break;
        const uint8_t *fenc=wire+woff;woff+=(size_t)fesz;
        snprintf(lbl,sizeof(lbl),"file:%s/%s",cl,relpath);
        const char *fpw=kf_get(w->kf,lbl);
        if(!fpw){free(wire);sem_post_s(w->slot);dprintf(STDERR_FILENO,"rv: missing key: %s\n",lbl);die("Z");}
        size_t plain_sz; uint8_t *plain=otc_decrypt(fenc,(size_t)fesz,fpw,&plain_sz);
        if(!plain){free(wire);sem_post_s(w->slot);die("Z");}
        char out_path[MAX_PATH_LEN]; snprintf(out_path,sizeof(out_path),"%s/%s",w->out_dir,relpath);
        char tmp[MAX_PATH_LEN]; strncpy(tmp,out_path,sizeof(tmp)-1);
        for(char *p=tmp+1;*p;p++) if(*p=='/'){*p='\0';if(mkdir(tmp,0755)<0 && errno!=EEXIST){dprintf(STDERR_FILENO,"rv: mkdir failure %s\n",tmp);die("M");}*p='/';}
        wfile(out_path,plain,plain_sz); sodium_memzero(plain,plain_sz); free(plain);
    }
    sodium_memzero(wire,wire_sz); free(wire);
    sem_post_s(w->slot); return NULL;
}

/* ================================================================== */
/* Decode: <base>_root.otc + <base>.key → original folder             */
/* ================================================================== */
static void decode_otc(const char *cont_path,const char *key_path,int ignore_swap){
    g_ignore_swap_failsafe = ignore_swap;
    char base[MAX_PATH_LEN]; strncpy(base,cont_path,sizeof(base)-1);base[sizeof(base)-1]='\0';
    char *slash=strrchr(base,'/');
    char *bname=slash?slash+1:base;
    char *suf=strstr(bname,"_root.otc");
    if(!suf){suf=strstr(bname,".otc");if(!suf)die("Z: unrecognised extension");}
    char folder_name[MAX_PATH_LEN]; size_t blen=(size_t)(suf-bname);
    memcpy(folder_name,bname,blen);folder_name[blen]='\0';
    char out_dir[MAX_PATH_LEN];
    if(slash){char dir[MAX_PATH_LEN];size_t dlen=(size_t)(slash-base);memcpy(dir,base,dlen);dir[dlen]='\0';snprintf(out_dir,sizeof(out_dir),"%s/%s",dir,folder_name);}
    else       snprintf(out_dir,sizeof(out_dir),"%s",folder_name);

    /* Set up persistent fail counter path */
    {
        char tmp[MAX_PATH_LEN]; strncpy(tmp,cont_path,sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
        char *ext=strstr(tmp,"_root.otc"); if(ext)*ext='\0';
        else { ext=strrchr(tmp,'.'); if(ext)*ext='\0'; }
        snprintf(g_fail_path,sizeof(g_fail_path),"%s.fails",tmp);
    }

    /* Check fail count before even prompting */
    {
        int n=fail_count_read();
        if(n>=WIPE_FAIL_LIMIT){
            dprintf(STDERR_FILENO,"rv: fail limit reached — destroying %s\n",cont_path);
            fail_count_hit(cont_path);
        }
    }

    KeyFile kf; kf_read(&kf,key_path);
    { struct stat st; if(stat(cont_path,&st)==0) printf("Reading %s (%lld bytes)...\n",cont_path,(long long)st.st_size); }
    size_t root_enc_sz; uint8_t *root_enc=rfile(cont_path,&root_enc_sz);
    const char *root_pw=kf_get(&kf,"root");
    if(!root_pw){free(root_enc);kf_free(&kf);fail_count_hit(cont_path);die("Z: no root password");}

    printf("Decrypting root archive...\n");
    check_swap_usage();
    size_t root_sz; uint8_t *root_data=otc_decrypt(root_enc,root_enc_sz,root_pw,&root_sz);
    free(root_enc);
    if(root_sz<12||memcmp(root_data,CONT_MAGIC,8)!=0){
        free(root_data);kf_free(&kf);fail_count_hit(cont_path);die("M: bad root magic / wrong password");
    }

    /* Successful decryption — reset fail counter */
    fail_count_reset();

    uint32_t nconts=r32(root_data+8); size_t off=12;
    int ncpus=cpu_count(); int slots=ncpus*2; if(slots<2)slots=2;
    printf("Decoding %u container(s)  [%d CPUs, %d concurrent]\n",nconts,ncpus,slots);
    mkdir(out_dir,0755);

    Sem slot_sem; sem_setup(&slot_sem,slots);
    DecWork *work=calloc(nconts,sizeof(DecWork));
    pthread_t *tids=malloc(nconts*sizeof(pthread_t));
    if(!work||!tids)die("N");

    for(uint32_t ci=0;ci<nconts;ci++){
        if(off+2>root_sz)break;
        uint16_t cnl=r16(root_data+off);off+=2;
        if(off+cnl>root_sz)break;
        memcpy(work[ci].cont_name,root_data+off,cnl);work[ci].cont_name[cnl]='\0';off+=cnl;
        if(off+8>root_sz)break;
        uint64_t esz=r64(root_data+off);off+=8;
        if(off+esz>root_sz)break;
        work[ci].enc=root_data+off; work[ci].enc_sz=(size_t)esz;
        work[ci].out_dir=out_dir; work[ci].kf=&kf; work[ci].slot=&slot_sem;
        off+=(size_t)esz;
        sem_wait_s(&slot_sem);
        pthread_create(&tids[ci],NULL,dec_worker,&work[ci]);
    }
    for(uint32_t ci=0;ci<nconts;ci++){
        check_swap_usage();
        pthread_join(tids[ci],NULL);
        printf("\r  [Decoding] "); draw_progress(ci+1,nconts); printf("  %u/%u containers\n",ci+1,nconts);
    }
    sem_destroy_s(&slot_sem); free(work); free(tids);
    sodium_memzero(root_data,root_sz); free(root_data);
    unlink(cont_path); unlink(key_path);
    printf("Decoded: %s/\n",out_dir);
    kf_free(&kf);
}

/* ================================================================== */
/* In-memory execution                                                  */
/* Linux: memfd_create + fexecve (payload never touches disk)          */
/* Other POSIX: mkstemp + exec + secure wipe + unlink                  */
/* ================================================================== */
#ifndef MFD_CLOEXEC
# define MFD_CLOEXEC 1U
#endif
static void plat_exec_payload(const uint8_t *data,size_t len){
#if defined(__linux__) && defined(SYS_memfd_create)
    int mfd=(int)syscall(SYS_memfd_create,".",MFD_CLOEXEC);
    if(mfd<0)_exit(1);
    size_t done=0;
    while(done<len){ssize_t r=write(mfd,data+done,len-done);if(r<=0){close(mfd);_exit(1);}done+=(size_t)r;}
    char *const ea[]={(char*)".",NULL}; char *const ev[]={NULL};
    pid_t pid=fork(); if(pid<0){close(mfd);_exit(1);}
    if(pid==0){fexecve(mfd,ea,ev);_exit(127);}
    close(mfd); int st; waitpid(pid,&st,0);
#else
    /* POSIX fallback: secure temp file */
    char tmp[]="/tmp/.rvXXXXXX";
    int fd=mkstemp(tmp); if(fd<0)_exit(1);
    size_t done=0;
    while(done<len){ssize_t r=write(fd,data+done,len-done);if(r<=0){close(fd);unlink(tmp);_exit(1);}done+=(size_t)r;}
    close(fd);
    if(chmod(tmp,0700)!=0){unlink(tmp);_exit(1);}
    pid_t pid=fork(); if(pid<0){unlink(tmp);_exit(1);}
    if(pid==0){execl(tmp,tmp,(char*)NULL);_exit(127);}
    int st; waitpid(pid,&st,0);
    /* Overwrite before unlink */
    { int wfd=open(tmp,O_WRONLY);
      if(wfd>=0){
        uint8_t z[4096]; memset(z,0,sizeof(z));
        size_t p=0; while(p<len){write(wfd,z,sizeof(z));p+=sizeof(z);}
        close(wfd);
      }}
    unlink(tmp);
#endif
}

/* ================================================================== */
/* run_secure                                                           */
/* ================================================================== */
static void run_secure(const char *path,const char *pw){
    STACK_CANARY_INIT(); STACK_CANARY_SAVE(); RE_GUARD();
    if(!g_allow_vm && plat_is_vm()) die("V");
    if(are_debugged()) die("D");
    if(geteuid()==0)   die("R");
    ANTIDIS_TRAP2();
    size_t il; uint8_t *plain=read_rv5c(path,pw,NULL,NULL,NULL,&il);
    plat_exec_payload(plain,il);
    sodium_memzero(plain,il); free(plain);
    STACK_CANARY_CHECK();
}

/* ================================================================== */
/* Main                                                                 */
/*                                                                      */
/*  ./rv encode <folder|file> [remove]                                 */
/*  ./rv decode <name_root.otc> <name.key>                             */
/*  ./rv run    <file>                                                  */
/* ================================================================== */
int main(int argc, char **argv) {
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║  RV – HAPPY ENCODING                                 ║\n");
    printf("║  Build: v6 | Crypto: ML-KEM-1024 + SHAKE-256        ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");

    anti_re_init();
    wipe_handler_install();

    if(sodium_init() < 0){
        fprintf(stderr,"Failed to initialize sodium library.\n"); _exit(1);
    }

    if(argc < 2){
        dprintf(STDERR_FILENO,
            "usage:\n"
            "  %s encode  <folder|file> [-r] [-i]\n"
            "             [--files-per-container N] [--no-compress]\n"
            "  %s decode  <name_root.otc> <name.key> [-i]\n"
            "  %s verify  <name_root.otc> <name.key>\n"
            "  %s run     <file> [--allow-vm]\n"
            "  %s [--mode rv2] encode|decode|run ...\n"
            "\nflags (encode):\n"
            "  -r                     secure-delete source files after encode\n"
            "  -i                     ignore RAM/swap safety check\n"
            "  --files-per-container N  files per sub-container (default: %d)\n"
            "  --no-compress          skip LZ4 compression\n"
            "\nflags (decode):\n"
            "  -i                     ignore RAM/swap safety check\n"
            "\nflags (run):\n"
            "  --allow-vm             allow execution inside a VM\n",
            argv[0],argv[0],argv[0],argv[0],argv[0],FILES_PER_CONT_DEFAULT);
        return 1;
    }

    /* Legacy rv2 mode */
    if(argc>=3 && !strcmp(argv[1],"--mode") && !strcmp(argv[2],"rv2")){
        if(argc < 5){ rv2_usage(argv[0]); return 1; }
        const char *cmd=argv[3], *path=argv[4];
        const char *pw=(argc>5)?argv[5]:NULL;
        int backup=(argc>=7&&!strcmp(argv[6],"backup"));
        char real_path[PATH_MAX];
        if(realpath(path,real_path)==NULL){perror("realpath");return 1;}
        path=real_path;
        if(!strcmp(cmd,"encode")){
            struct stat st; if(stat(path,&st)!=0){perror(path);return 1;}
            if(S_ISDIR(st.st_mode)) rv2_encode_folder(path,pw,backup);
            else                    rv2_encode_file(path,pw,backup);
        } else if(!strcmp(cmd,"decode")){
            const char *ext=strrchr(path,'.');
            if(ext&&!strcmp(ext,".rv2")) rv2_decode_container(path,pw);
            else                         rv2_decode_file(path,pw);
        } else if(!strcmp(cmd,"run")){
            rv2_run(path,pw);
        } else {
            dprintf(STDERR_FILENO,"rv2: unknown command: %s\n",cmd);
            rv2_usage(argv[0]); return 1;
        }
        return 0;
    }

    const char *cmd = argv[1];

    /* Parse all flags from argv */
    int ignore_swap=0, remove_after=0;
    for(int i=2;i<argc;i++){
        if(!strcmp(argv[i],"-i"))                    ignore_swap=1;
        if(!strcmp(argv[i],"-r"))                    remove_after=1;
        if(!strcmp(argv[i],"--allow-vm"))            g_allow_vm=1;
        if(!strcmp(argv[i],"--no-compress"))         g_no_compress=1;
        if(!strcmp(argv[i],"--files-per-container") && i+1<argc){
            int n=atoi(argv[i+1]);
            if(n<1||n>10000){dprintf(STDERR_FILENO,"rv: --files-per-container must be 1..10000\n");return 1;}
            g_files_per_cont=n; i++;
        }
    }

    if(argc < 3 && strcmp(cmd,"verify")!=0){
        dprintf(STDERR_FILENO,"rv: missing argument\n"); return 1;
    }
    const char *path = (argc>=3)?argv[2]:NULL;
    if(path && strstr(path,".."))_exit(1);

    if(!strcmp(cmd,"encode")){
        if(!path){dprintf(STDERR_FILENO,"usage: %s encode <folder|file> [flags]\n",argv[0]);return 1;}
        struct stat st;
        if(stat(path,&st)!=0){perror(path);return 1;}
        if(S_ISDIR(st.st_mode)){
            encode_otc(path, remove_after, ignore_swap);
        } else {
            /* Single file */
            const char *slash=strrchr(path,'/');
            const char *fname=slash?slash+1:path;
            char base[MAX_PATH_LEN]; strncpy(base,fname,sizeof(base)-1); base[sizeof(base)-1]='\0';
            { char *dot=strrchr(base,'.'); if(dot&&dot!=base)*dot='\0'; }

            g_ignore_swap_failsafe=ignore_swap;
            check_swap_usage();

            KeyFile kf; kf_init(&kf);
            char root_pw[ROOT_PW_LEN+1]; gen_password(root_pw); kf_add(&kf,"root",root_pw);
            char cont_name[MAX_PATH_LEN]; snprintf(cont_name,sizeof(cont_name),"%s_1.cont",base);
            char cont_pw[CONT_PW_LEN+1]; gen_password(cont_pw);
            char cont_label[MAX_PATH_LEN]; snprintf(cont_label,sizeof(cont_label),"cont:%s",cont_name); kf_add(&kf,cont_label,cont_pw);
            char fpw[FILE_PW_LEN+1]; gen_password(fpw);
            char clabel[MAX_PATH_LEN]; strncpy(clabel,cont_name,sizeof(clabel)-1); clabel[sizeof(clabel)-1]='\0';
            char *dp=strstr(clabel,".cont"); if(dp)*dp='\0';
            char file_label[MAX_PATH_LEN]; snprintf(file_label,sizeof(file_label),"file:%s/%s",clabel,fname); kf_add(&kf,file_label,fpw);

            size_t fsz; uint8_t *fdata=rfile(path,&fsz);
            size_t efsz; uint8_t *efdata=otc_encrypt(fdata,fsz,fpw,&efsz);
            sodium_memzero(fdata,fsz); free(fdata); sodium_memzero(fpw,FILE_PW_LEN);

            BB wire; bb_init(&wire); bb_app(&wire,CONT_MAGIC,8);
            uint8_t fc[4]; w32(fc,1); bb_app(&wire,fc,4);
            size_t rplen=strlen(fname); uint8_t rpl[2]; w16(rpl,(uint16_t)rplen); bb_app(&wire,rpl,2);
            bb_app(&wire,fname,rplen);
            uint8_t dl[8]; w64(dl,(uint64_t)efsz); bb_app(&wire,dl,8);
            bb_app(&wire,efdata,efsz); free(efdata);

            size_t esz; uint8_t *enc=otc_encrypt(wire.d,wire.sz,cont_pw,&esz);
            sodium_memzero(wire.d,wire.sz); bb_free(&wire); sodium_memzero(cont_pw,CONT_PW_LEN);

            BB ra; bb_init(&ra); bb_app(&ra,CONT_MAGIC,8);
            uint8_t nc[4]; w32(nc,1); bb_app(&ra,nc,4);
            size_t cnl=strlen(cont_name); uint8_t cnl_b[2]; w16(cnl_b,(uint16_t)cnl); bb_app(&ra,cnl_b,2);
            bb_app(&ra,cont_name,cnl);
            uint8_t esz_b[8]; w64(esz_b,(uint64_t)esz); bb_app(&ra,esz_b,8);
            bb_app(&ra,enc,esz); free(enc);

            size_t root_enc_sz; uint8_t *root_enc=otc_encrypt(ra.d,ra.sz,root_pw,&root_enc_sz);
            sodium_memzero(ra.d,ra.sz); bb_free(&ra); sodium_memzero(root_pw,ROOT_PW_LEN);

            char opath[MAX_PATH_LEN],key_path[MAX_PATH_LEN];
            snprintf(opath,sizeof(opath),"%s_root.otc",base);
            snprintf(key_path,sizeof(key_path),"%s.key",base);
            wfile(opath,root_enc,root_enc_sz); free(root_enc);
            kf_write(&kf,key_path); kf_free(&kf);
            printf("Created: %s\n",opath);
            printf("Created: %s (encrypted)\n",key_path);

            if(remove_after){
                /* 3-pass secure wipe of single source file */
                struct stat st2; if(stat(path,&st2)==0){
                    size_t fsz2=(size_t)st2.st_size;
                    int fd=open(path,O_WRONLY); if(fd>=0&&fsz2>0){
                        uint8_t *buf=malloc(65536); if(buf){
                            for(int pass=0;pass<3;pass++){
                                lseek(fd,0,SEEK_SET); size_t done=0;
                                while(done<fsz2){
                                    size_t chunk=fsz2-done; if(chunk>65536)chunk=65536;
                                    if(pass==1)memset(buf,0,chunk); else randombytes_buf(buf,chunk);
                                    write(fd,buf,chunk); done+=chunk;
                                }
                                fsync(fd);
                            }
                            free(buf);
                        }
                        close(fd);
                    } else if(fd>=0) close(fd);
                }
                unlink(path);
                printf("Securely removed: %s\n",path);
            }
        }

    } else if(!strcmp(cmd,"decode")){
        if(argc<4){dprintf(STDERR_FILENO,"usage: %s decode <root.otc> <key> [-i]\n",argv[0]);return 1;}
        const char *key_path=argv[3];
        if(strstr(key_path,".."))_exit(1);
        decode_otc(path,key_path,ignore_swap);

    } else if(!strcmp(cmd,"verify")){
        if(argc<4){dprintf(STDERR_FILENO,"usage: %s verify <root.otc> <key>\n",argv[0]);return 1;}
        const char *key_path=argv[3];
        if(strstr(key_path,".."))_exit(1);
        verify_otc(path,key_path);

    } else if(!strcmp(cmd,"run")){
        char pw[MAX_PW_LEN]; memset(pw,0,sizeof(pw));
        DECSTR(prompt,"Password: ");
        read_pw(pw,sizeof(pw),prompt); sodium_memzero(prompt,sizeof(prompt));
        run_secure(path,pw); sodium_memzero(pw,sizeof(pw));

    } else {
        dprintf(STDERR_FILENO,"unknown command: %s\n",cmd); return 1;
    }
    return 0;
}
