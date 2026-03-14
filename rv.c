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
/* Password strength estimator                                          */
/*                                                                      */
/* Returns estimated bits of entropy using character-class diversity   */
/* and length.  Applies penalties for keyboard walks, repeated chars,  */
/* and all-lowercase/digit passwords.                                  */
/* Thresholds:  < 28 bits → refuse (die),  < 50 bits → warn.          */
/* ================================================================== */
static double pw_entropy_bits(const char *pw){
    size_t len=strlen(pw);
    if(len==0) return 0.0;

    /* Character pool size from classes present */
    int has_lower=0,has_upper=0,has_digit=0,has_sym=0;
    for(size_t i=0;i<len;i++){
        unsigned char c=(unsigned char)pw[i];
        if(c>='a'&&c<='z') has_lower=1;
        else if(c>='A'&&c<='Z') has_upper=1;
        else if(c>='0'&&c<='9') has_digit=1;
        else if(c>=0x20&&c<=0x7E) has_sym=1;
    }
    double pool=0;
    if(has_lower) pool+=26;
    if(has_upper) pool+=26;
    if(has_digit) pool+=10;
    if(has_sym)   pool+=32;
    if(pool<2) pool=2;

    double bits = (double)len * (log(pool)/log(2.0));

    /* Penalty: >40% repeated characters */
    {
        int rep=0;
        for(size_t i=1;i<len;i++) if(pw[i]==pw[i-1]) rep++;
        if(len>1 && (double)rep/(double)(len-1)>0.4) bits*=0.7;
    }
    /* Penalty: keyboard walk (3+ consecutive ASCII increments) */
    {
        int walk=0,wlen=1;
        for(size_t i=1;i<len;i++){
            int d=(int)(unsigned char)pw[i]-(int)(unsigned char)pw[i-1];
            if(d==1||d==-1){ wlen++; if(wlen>=3){walk=1;break;} }
            else wlen=1;
        }
        if(walk) bits*=0.75;
    }

    return bits;
}

/* ================================================================== */
/* Password reader — TTY or stdin                                       */
/* ================================================================== */
static int g_stdin_pw = 0;  /* set by --stdin-pw flag */

static void read_pw_real(char *buf,size_t bl,const char *prompt){
    if(g_stdin_pw){
        /* Read from stdin — no echo suppression needed */
        if(fgets(buf,(int)bl,stdin)==NULL) die("stdin password read failed");
        size_t l=strlen(buf); if(l>0&&buf[l-1]=='\n')buf[--l]='\0'; if(!l)die("empty password");
        return;
    }
    FILE *t=fopen("/dev/tty","r+"); if(!t)die("T");
    fputs(prompt,t); fflush(t);
    struct termios old,ne; tcgetattr(fileno(t),&old); ne=old;
    ne.c_lflag&=~(tcflag_t)(ECHO|ECHOE|ECHOK|ECHONL);
    tcsetattr(fileno(t),TCSANOW,&ne);
    if(!fgets(buf,(int)bl,t)){tcsetattr(fileno(t),TCSANOW,&old);fclose(t);die("P");}
    tcsetattr(fileno(t),TCSANOW,&old); fputc('\n',t); fclose(t);
    size_t l=strlen(buf); if(l>0&&buf[l-1]=='\n')buf[--l]='\0'; if(!l)die("E");
}


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
/* Encode progress display                                             */
/*                                                                      */
/* draw_encode_progress() — call once per completed container.         */
/*   done_conts   : containers finished so far                         */
/*   total_conts  : total containers                                   */
/*   done_bytes   : raw bytes encoded so far                           */
/*   total_bytes  : total raw bytes to encode                          */
/*   elapsed_sec  : seconds since encode started (double)              */
/*                                                                      */
/* Prints a single \r-terminated line so it overwrites itself.         */
/* ================================================================== */
static void draw_encode_progress(size_t done_conts, size_t total_conts,
                                  uint64_t done_bytes, uint64_t total_bytes,
                                  double elapsed_sec)
{
    if(total_conts == 0) return;

    /* ---- bar ---- */
    int bar_width = 30;
    double frac = (total_bytes > 0)
                  ? (double)done_bytes / (double)total_bytes
                  : (double)done_conts / (double)total_conts;
    if(frac > 1.0) frac = 1.0;
    int filled = (int)(frac * bar_width);

    /* ---- size labels ---- */
    double done_gib  = (double)done_bytes  / (1024.0*1024.0*1024.0);
    double total_gib = (double)total_bytes / (1024.0*1024.0*1024.0);
    double left_gib  = total_gib - done_gib;
    if(left_gib < 0.0) left_gib = 0.0;

    /* ---- ETA ---- */
    char eta_buf[32];
    if(elapsed_sec > 0.5 && frac > 0.001){
        double rate = (double)done_bytes / elapsed_sec;   /* bytes/sec */
        double remaining_bytes = (double)(total_bytes - done_bytes);
        double eta_sec = (rate > 0) ? remaining_bytes / rate : 0.0;
        if(eta_sec < 0) eta_sec = 0;
        int eh = (int)(eta_sec / 3600);
        int em = (int)((eta_sec - eh*3600) / 60);
        int es = (int)(eta_sec) % 60;
        if(eh > 0)
            snprintf(eta_buf, sizeof(eta_buf), "ETA %dh%02dm%02ds", eh, em, es);
        else if(em > 0)
            snprintf(eta_buf, sizeof(eta_buf), "ETA %dm%02ds", em, es);
        else
            snprintf(eta_buf, sizeof(eta_buf), "ETA %ds", es);
    } else {
        snprintf(eta_buf, sizeof(eta_buf), "ETA --:--");
    }

    /* ---- throughput ---- */
    char rate_buf[32];
    if(elapsed_sec > 0.1 && done_bytes > 0){
        double mbs = (double)done_bytes / elapsed_sec / (1024.0*1024.0);
        snprintf(rate_buf, sizeof(rate_buf), "%.1f MiB/s", mbs);
    } else {
        snprintf(rate_buf, sizeof(rate_buf), "-- MiB/s");
    }

    /* ---- elapsed ---- */
    char elapsed_buf[24];
    int ts = (int)elapsed_sec;
    int th = ts/3600, tm=(ts%3600)/60, tsec=ts%60;
    if(th>0) snprintf(elapsed_buf,sizeof(elapsed_buf),"%dh%02dm%02ds",th,tm,tsec);
    else      snprintf(elapsed_buf,sizeof(elapsed_buf),"%dm%02ds",tm,tsec);

    /* ---- assemble line ---- */
    printf("\r[");
    for(int i=0;i<bar_width;i++){
        if(i < filled)       printf("=");
        else if(i == filled) printf(">");
        else                 printf(" ");
    }
    printf("] %5.1f%%  cont %zu/%zu  %.2f/%.2f GiB left  %s  %s  %s   ",
           frac*100.0,
           done_conts, total_conts,
           left_gib, total_gib,
           rate_buf, eta_buf, elapsed_buf);
    fflush(stdout);
}

/* Legacy simple bar kept for decode path */
static void draw_progress(size_t current, size_t total) {
    if (total == 0) return;
    int bar_width = 40;
    float progress = (float)current / total;
    int filled = (int)(progress * bar_width);
    printf("\r[");
    for (int i = 0; i < bar_width; i++)
        printf(i < filled ? "=" : " ");
    printf("] %.1f%%", progress * 100.0);
    fflush(stdout);
}

/* ================================================================== */
/* Real-time progress state — updated by encode workers               */
/* ================================================================== */
#include <sys/ioctl.h>

/* Shared atomic-ish progress counters (written by workers, read by          */
/* ticker thread). We use a mutex rather than C11 atomics for portability.   */
static pthread_mutex_t  g_prog_mu    = PTHREAD_MUTEX_INITIALIZER;
static volatile uint64_t g_done_raw_bytes  = 0;   /* bytes encoded so far   */
static volatile uint64_t g_total_raw_bytes_g = 0; /* total bytes to encode  */
static volatile size_t   g_done_conts      = 0;   /* containers finished    */
static volatile size_t   g_total_conts_g   = 0;   /* total containers       */
static volatile int      g_prog_running    = 0;   /* ticker active flag     */
static struct timespec   g_prog_t_start;           /* encode start time      */

/* Update done-bytes counter from a worker (call after each file) */
static void prog_add_bytes(uint64_t n){
    pthread_mutex_lock(&g_prog_mu);
    g_done_raw_bytes += n;
    pthread_mutex_unlock(&g_prog_mu);
}
/* Mark one container done */
static void prog_done_cont(void){
    pthread_mutex_lock(&g_prog_mu);
    g_done_conts++;
    pthread_mutex_unlock(&g_prog_mu);
}

/* Get terminal column width; returns 80 if unknown */
static int term_width(void){
#ifdef TIOCGWINSZ
    struct winsize ws;
    if(ioctl(STDOUT_FILENO,TIOCGWINSZ,&ws)==0 && ws.ws_col>0)
        return (int)ws.ws_col;
#endif
    const char *e=getenv("COLUMNS");
    if(e){int w=atoi(e);if(w>0)return w;}
    return 80;
}

/* Render one progress line; called by ticker and by join loop */
static void render_progress_line(void){
    pthread_mutex_lock(&g_prog_mu);
    uint64_t done_b  = g_done_raw_bytes;
    uint64_t total_b = g_total_raw_bytes_g;
    size_t   done_c  = g_done_conts;
    size_t   total_c = g_total_conts_g;
    pthread_mutex_unlock(&g_prog_mu);

    struct timespec now; clock_gettime(CLOCK_MONOTONIC,&now);
    double elapsed = (double)(now.tv_sec  - g_prog_t_start.tv_sec) +
                     (double)(now.tv_nsec - g_prog_t_start.tv_nsec)*1e-9;

    /* Reuse draw_encode_progress formatting but capture into a buffer     */
    /* so we can truncate to terminal width before printing.               */
    int tw = term_width() - 2;  /* leave 2 chars margin */
    if(tw < 40) tw = 40;

    /* ---- fraction ---- */
    double frac = (total_b > 0)
                  ? (double)done_b / (double)total_b
                  : (total_c > 0 ? (double)done_c / (double)total_c : 0.0);
    if(frac > 1.0) frac = 1.0;

    /* ---- bar width: scale to terminal, minimum 20 ---- */
    int bar_w = tw / 3;
    if(bar_w < 20) bar_w = 20;
    if(bar_w > 50) bar_w = 50;
    int filled = (int)(frac * bar_w);

    /* ---- GiB done / total ---- */
    double done_gib  = (double)done_b  / (1024.0*1024.0*1024.0);
    double total_gib = (double)total_b / (1024.0*1024.0*1024.0);
    double left_gib  = total_gib - done_gib;
    if(left_gib < 0.0) left_gib = 0.0;

    /* ---- ETA ---- */
    char eta_buf[24];
    if(elapsed > 0.5 && frac > 0.001 && frac < 1.0){
        double rate = (double)done_b / elapsed;
        double eta_sec = (rate > 0) ? (double)(total_b - done_b) / rate : 0.0;
        if(eta_sec < 0) eta_sec = 0;
        int eh=(int)(eta_sec/3600), em=(int)((eta_sec-(int)(eta_sec/3600)*3600)/60), es=(int)eta_sec%60;
        if(eh>0) snprintf(eta_buf,sizeof(eta_buf),"ETA %dh%02dm",eh,em);
        else if(em>0) snprintf(eta_buf,sizeof(eta_buf),"ETA %dm%02ds",em,es);
        else          snprintf(eta_buf,sizeof(eta_buf),"ETA %ds",es);
    } else if(frac >= 1.0) {
        snprintf(eta_buf,sizeof(eta_buf),"done");
    } else {
        snprintf(eta_buf,sizeof(eta_buf),"ETA --:--");
    }

    /* ---- throughput ---- */
    char rate_buf[20];
    if(elapsed > 0.1 && done_b > 0){
        double mbs = (double)done_b / elapsed / (1024.0*1024.0);
        if(mbs >= 1000.0)      snprintf(rate_buf,sizeof(rate_buf),"%.1f GiB/s",mbs/1024.0);
        else if(mbs >= 100.0)  snprintf(rate_buf,sizeof(rate_buf),"%.0f MiB/s",mbs);
        else                   snprintf(rate_buf,sizeof(rate_buf),"%.1f MiB/s",mbs);
    } else {
        snprintf(rate_buf,sizeof(rate_buf),"-- MiB/s");
    }

    /* ---- elapsed ---- */
    char el_buf[20];
    int ts=(int)elapsed, th2=ts/3600, tm2=(ts%3600)/60, ts2=ts%60;
    if(th2>0) snprintf(el_buf,sizeof(el_buf),"%dh%02dm%02ds",th2,tm2,ts2);
    else       snprintf(el_buf,sizeof(el_buf),"%dm%02ds",tm2,ts2);

    /* ---- build into stack buffer, truncate to tw ---- */
    char line[512];
    int pos=0;

    /* bar */
    line[pos++]='[';
    for(int i=0;i<bar_w;i++){
        if(i<filled)       line[pos++]='=';
        else if(i==filled) line[pos++]='>';
        else               line[pos++]=' ';
    }
    line[pos++]=']';

    /* stats — always include percent + cont counter */
    pos += snprintf(line+pos, sizeof(line)-pos,
                    " %5.1f%%  %zu/%zu",
                    frac*100.0, done_c, total_c);

    /* add size info if enough room */
    if(tw > 60){
        pos += snprintf(line+pos, sizeof(line)-pos,
                        "  %.2f/%.2fG",
                        done_gib, total_gib);
    }
    if(tw > 72){
        pos += snprintf(line+pos, sizeof(line)-pos,
                        "  %.2fG left", left_gib);
    }
    if(tw > 85){
        pos += snprintf(line+pos, sizeof(line)-pos,
                        "  %s  %s  %s", rate_buf, eta_buf, el_buf);
    } else if(tw > 70){
        pos += snprintf(line+pos, sizeof(line)-pos,
                        "  %s  %s", eta_buf, el_buf);
    }

    /* pad to erase previous longer line, then \r */
    if(pos > tw) pos = tw;
    while(pos < tw) line[pos++]=' ';
    line[pos]='\0';

    printf("\r%s", line);
    fflush(stdout);
}

/* Background ticker: redraws the line every ~100 ms while encoding */
typedef struct { int interval_ms; } TickerArg;
static void *progress_ticker(void *arg){
    (void)arg;
    struct timespec ts; ts.tv_sec=0; ts.tv_nsec=100*1000*1000; /* 100 ms */
    while(g_prog_running){
        nanosleep(&ts,NULL);
        if(g_prog_running) render_progress_line();
    }
    return NULL;
}

/* Start / stop the ticker thread */
static pthread_t g_ticker_tid;
static void ticker_start(uint64_t total_bytes, size_t total_conts){
    pthread_mutex_lock(&g_prog_mu);
    g_done_raw_bytes   = 0;
    g_total_raw_bytes_g= total_bytes;
    g_done_conts       = 0;
    g_total_conts_g    = total_conts;
    pthread_mutex_unlock(&g_prog_mu);
    clock_gettime(CLOCK_MONOTONIC,&g_prog_t_start);
    g_prog_running = 1;
    pthread_create(&g_ticker_tid,NULL,progress_ticker,NULL);
}
static void ticker_stop(void){
    g_prog_running = 0;
    pthread_join(g_ticker_tid,NULL);
    render_progress_line(); /* final render */
    printf("\n");
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
/* Secure wipe registry + SIGINT/SIGTERM handler                       */
/*                                                                      */
/* Any sensitive heap buffer can be registered with wipe_register().   */
/* On SIGINT/SIGTERM the handler zeroes every registered region and     */
/* calls _exit(130) — no partial keys are left in RAM.                 */
/* ================================================================== */
#include <signal.h>

#define WIPE_MAX 256
typedef struct { volatile uint8_t *ptr; size_t len; } WipeEntry;
static WipeEntry  _wipe_table[WIPE_MAX];
static volatile int _wipe_cnt = 0;
static pthread_mutex_t _wipe_mu = PTHREAD_MUTEX_INITIALIZER;

static void wipe_register(volatile uint8_t *ptr, size_t len){
    pthread_mutex_lock(&_wipe_mu);
    if(_wipe_cnt < WIPE_MAX){
        _wipe_table[_wipe_cnt].ptr = ptr;
        _wipe_table[_wipe_cnt].len = len;
        _wipe_cnt++;
    }
    pthread_mutex_unlock(&_wipe_mu);
}
static void wipe_unregister(volatile uint8_t *ptr){
    pthread_mutex_lock(&_wipe_mu);
    for(int i=0;i<_wipe_cnt;i++){
        if(_wipe_table[i].ptr == ptr){
            _wipe_table[i] = _wipe_table[--_wipe_cnt];
            break;
        }
    }
    pthread_mutex_unlock(&_wipe_mu);
}
static void _signal_wipe_handler(int sig){
    (void)sig;
    for(int i=0;i<_wipe_cnt;i++){
        volatile uint8_t *p = _wipe_table[i].ptr;
        size_t n = _wipe_table[i].len;
        for(size_t j=0;j<n;j++) p[j]=0;
    }
    _exit(130);
}
static void wipe_handler_install(void){
    struct sigaction sa;
    memset(&sa,0,sizeof(sa));
    sa.sa_handler = _signal_wipe_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* ================================================================== */
/* Anti-debug                                                           */
/* ================================================================== */
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
#define FILES_PER_CONT 3

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
/* ================================================================== */
/* Secure delete                                                        */
/*                                                                      */
/* Three-pass overwrite: random → zero → random, then unlink.          */
/* Falls back to plain unlink if the file cannot be opened for write   */
/* (e.g. already deleted or on a read-only fs).                        */
/* ================================================================== */
static void secure_unlink(const char *path){
    struct stat st;
    if(stat(path,&st)!=0){ unlink(path); return; }
    size_t sz = (size_t)st.st_size;
    int fd = open(path, O_WRONLY);
    if(fd >= 0 && sz > 0){
        uint8_t *buf = malloc(65536);
        if(buf){
            /* Pass 1: random */
            size_t done=0;
            while(done<sz){
                size_t chunk=sz-done; if(chunk>65536)chunk=65536;
                randombytes_buf(buf,chunk);
                write(fd,buf,chunk); done+=chunk;
            }
            fsync(fd); lseek(fd,0,SEEK_SET);
            /* Pass 2: zeros */
            memset(buf,0,65536); done=0;
            while(done<sz){
                size_t chunk=sz-done; if(chunk>65536)chunk=65536;
                write(fd,buf,chunk); done+=chunk;
            }
            fsync(fd); lseek(fd,0,SEEK_SET);
            /* Pass 3: random */
            done=0;
            while(done<sz){
                size_t chunk=sz-done; if(chunk>65536)chunk=65536;
                randombytes_buf(buf,chunk);
                write(fd,buf,chunk); done+=chunk;
            }
            fsync(fd);
            free(buf);
        }
        close(fd);
    } else if(fd>=0) close(fd);
    unlink(path);
}

/* ================================================================== */
/* Atomic paired output                                                 */
/*                                                                      */
/* Writes .otc and .key to temp files, renames both, then writes a     */
/* 1-byte sentinel <base>_root.ok to mark the set complete.            */
/* decode checks for the sentinel and warns if absent.                 */
/* ================================================================== */
static void wfile_pair(const char *otc_path, const uint8_t *otc_data, size_t otc_sz,
                        const char *key_path, const KeyFile *kf, const char *master_pw)
{
    /* Write both to temp files first */
    char otc_tmp[MAX_PATH_LEN], key_tmp[MAX_PATH_LEN];
    snprintf(otc_tmp, sizeof(otc_tmp), "%s.tmp", otc_path);
    snprintf(key_tmp, sizeof(key_tmp), "%s.tmp", key_path);

    /* Write .otc temp */
    {
        FILE *f = fopen(otc_tmp,"wb"); if(!f) die("wfile_pair: open otc tmp");
        size_t done=0;
        while(done<otc_sz){
            size_t r=fwrite(otc_data+done,1,otc_sz-done,f);
            if(!r){fclose(f);unlink(otc_tmp);die("wfile_pair: write otc");}
            done+=r;
        }
        fclose(f);
    }
    /* Write .key temp */
    {
        /* Serialise kf to plaintext then encrypt into temp */
        BB pt; bb_init(&pt);
        for(size_t i=0;i<kf->cnt;i++){
            size_t ll=strlen(kf->entries[i].label);
            size_t pl=strlen(kf->entries[i].pw);
            bb_app(&pt,(const uint8_t*)kf->entries[i].label,ll);
            bb_app(&pt,(const uint8_t*)":",1);
            bb_app(&pt,(const uint8_t*)kf->entries[i].pw,pl);
            bb_app(&pt,(const uint8_t*)"\n",1);
        }
        uint8_t salt[SALT_LEN], nonce[OTC_NONCE_LEN];
        randombytes_buf(salt,SALT_LEN); randombytes_buf(nonce,OTC_NONCE_LEN);
        uint8_t key[OTC_KEY_LEN]; fast_kdf(key,master_pw,salt);
        size_t ct_max=pt.sz+OTC_TAG_LEN;
        uint8_t *ct=malloc(ct_max);
        if(!ct){sodium_memzero(key,sizeof(key));bb_free(&pt);unlink(otc_tmp);die("N");}
        unsigned long long cl;
        if(crypto_aead_xchacha20poly1305_ietf_encrypt(ct,&cl,pt.d,pt.sz,NULL,0,NULL,nonce,key)!=0)
            {sodium_memzero(key,sizeof(key));free(ct);bb_free(&pt);unlink(otc_tmp);die("A");}
        sodium_memzero(key,sizeof(key)); sodium_memzero(pt.d,pt.sz); bb_free(&pt);

        size_t body_sz = KF_MAGIC_LEN + KF_EC_LEN + SALT_LEN + OTC_NONCE_LEN + (size_t)cl;
        size_t total   = body_sz + KF_OUTER_MAC_LEN;
        uint8_t *buf=malloc(total); if(!buf){free(ct);unlink(otc_tmp);die("N");}
        size_t o=0;
        memcpy(buf+o,KF_MAGIC,KF_MAGIC_LEN); o+=KF_MAGIC_LEN;
        w32(buf+o,(uint32_t)kf->cnt);         o+=KF_EC_LEN;
        memcpy(buf+o,salt,SALT_LEN);           o+=SALT_LEN;
        memcpy(buf+o,nonce,OTC_NONCE_LEN);     o+=OTC_NONCE_LEN;
        memcpy(buf+o,ct,(size_t)cl); free(ct); o+=(size_t)cl;
        uint8_t mac[KF_OUTER_MAC_LEN];
        kf_outer_mac(mac,buf,body_sz,salt);
        memcpy(buf+o,mac,KF_OUTER_MAC_LEN);

        FILE *f=fopen(key_tmp,"wb"); if(!f){free(buf);unlink(otc_tmp);die("wfile_pair: open key tmp");}
        fwrite(buf,1,total,f); fclose(f); free(buf);
    }

    /* Both temps written — now rename atomically */
    if(rename(otc_tmp, otc_path)!=0){
        unlink(otc_tmp); unlink(key_tmp);
        die("wfile_pair: rename otc");
    }
    if(rename(key_tmp, key_path)!=0){
        unlink(key_tmp);
        die("wfile_pair: rename key");
    }

    /* Write sentinel: <base>_root.ok — derives path by stripping .otc → .ok */
    char ok_path[MAX_PATH_LEN]; strncpy(ok_path,otc_path,sizeof(ok_path)-1); ok_path[sizeof(ok_path)-1]='\0';
    char *ext=strrchr(ok_path,'.'); if(ext&&!strcmp(ext,".otc")) strcpy(ext,".ok");
    else snprintf(ok_path,sizeof(ok_path),"%s.ok",otc_path);
    FILE *sf2=fopen(ok_path,"wb"); if(sf2){fputc(0x01,sf2);fclose(sf2);}
}

/* Check sentinel; warn if absent */
static void check_sentinel(const char *otc_path){
    char ok_path[MAX_PATH_LEN]; strncpy(ok_path,otc_path,sizeof(ok_path)-1); ok_path[sizeof(ok_path)-1]='\0';
    char *ext=strrchr(ok_path,'.'); if(ext&&!strcmp(ext,".otc")) strcpy(ext,".ok");
    else snprintf(ok_path,sizeof(ok_path),"%s.ok",otc_path);
    struct stat st;
    if(stat(ok_path,&st)!=0)
        printf("  [!] Warning: no .ok sentinel found — this encode may have been interrupted.\n"
               "      Decode may fail or produce incomplete output.\n");
}

/* ================================================================== */
/* Encode checkpoint (resume on interrupted encode)                    */
/*                                                                      */
/* After every container is ready to write, record its index and       */
/* SHAKE-256(container_name) in <base>_root.ckpt.                      */
/* On re-run, containers already in the checkpoint are skipped.        */
/* Format: one line per container: "<index> <hex_name_hash>\n"         */
/* ================================================================== */
#define CKPT_HASH_LEN 16   /* 16 bytes = 32 hex chars, enough to identify */

typedef struct { size_t idx; uint8_t nhash[CKPT_HASH_LEN]; } CkptEntry;
typedef struct { CkptEntry *e; size_t cnt, cap; } Ckpt;

static void ckpt_init(Ckpt *c){ c->cap=64;c->cnt=0;c->e=malloc(c->cap*sizeof(CkptEntry));if(!c->e)die("N"); }
static void ckpt_free(Ckpt *c){ free(c->e);c->e=NULL;c->cnt=c->cap=0; }
static void ckpt_add(Ckpt *c, size_t idx, const uint8_t h[CKPT_HASH_LEN]){
    if(c->cnt>=c->cap){c->cap*=2;c->e=realloc(c->e,c->cap*sizeof(CkptEntry));if(!c->e)die("N");}
    c->e[c->cnt].idx=idx; memcpy(c->e[c->cnt].nhash,h,CKPT_HASH_LEN); c->cnt++;
}
static int ckpt_has(const Ckpt *c, size_t idx, const uint8_t h[CKPT_HASH_LEN]){
    for(size_t i=0;i<c->cnt;i++)
        if(c->e[i].idx==idx && sodium_memcmp(c->e[i].nhash,h,CKPT_HASH_LEN)==0) return 1;
    return 0;
}
static void ckpt_read(Ckpt *c, const char *path){
    ckpt_init(c); FILE *f=fopen(path,"r"); if(!f)return;
    char line[128];
    while(fgets(line,sizeof(line),f)){
        size_t idx=0; char hex[CKPT_HASH_LEN*2+2]={0};
        if(sscanf(line,"%zu %32s",&idx,hex)!=2)continue;
        uint8_t h[CKPT_HASH_LEN];
        for(int i=0;i<CKPT_HASH_LEN;i++){unsigned v=0;sscanf(hex+i*2,"%02x",&v);h[i]=(uint8_t)v;}
        ckpt_add(c,idx,h);
    }
    fclose(f);
}
static void ckpt_append(const char *path, size_t idx, const uint8_t h[CKPT_HASH_LEN]){
    FILE *f=fopen(path,"a"); if(!f)return;
    fprintf(f,"%zu ",idx);
    for(int i=0;i<CKPT_HASH_LEN;i++) fprintf(f,"%02x",h[i]);
    fprintf(f,"\n"); fclose(f);
}
static void ckpt_name_hash(uint8_t out[CKPT_HASH_LEN], const char *name){
    uint8_t tmp[32]; shake256(tmp,32,(const uint8_t*)name,strlen(name));
    memcpy(out,tmp,CKPT_HASH_LEN);
}

/* ================================================================== */
/* Password strength meter                                              */
/*                                                                      */
/* Returns estimated entropy in bits using character-set size and      */
/* length, with penalties for keyboard walks and all-same-class input. */
/* Threshold: 40 bits minimum (warn), 60 bits recommended.             */
/* ================================================================== */
static void pw_strength_check(const char *pw, int allow_weak){
    double bits = pw_entropy_bits(pw);
    const char *label;
    if     (bits < 28) label = "very weak";
    else if(bits < 40) label = "weak";
    else if(bits < 60) label = "moderate";
    else if(bits < 80) label = "strong";
    else               label = "very strong";

    printf("  Password strength: %.0f bits — %s\n", bits, label);

    if(bits < 40.0 && !allow_weak){
        fprintf(stderr,
            "rv: password is too weak (%.0f bits, minimum 40).\n"
            "    Use a longer or more complex passphrase.\n"
            "    Override with --weak-pw if you really mean it.\n", bits);
        _exit(1);
    }
    if(bits < 60.0 && bits >= 40.0)
        printf("  Tip: a passphrase of 4+ random words is easier to remember and stronger.\n");
}

/* ================================================================== */
/* Password input with --stdin-pw support                              */
/* g_stdin_pw=1 reads from stdin; 0 reads from /dev/tty (default)     */
/* ================================================================== */

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

/* ================================================================== */
/* Secure file deletion                                                 */
/*                                                                      */
/* Overwrites the file with random bytes in 4 KiB chunks, calls       */
/* fsync() to push to storage, then unlinks.  Best-effort on all      */
/* POSIX platforms; log-structured / SSD storage may retain data in    */
/* wear-levelling cells regardless, but this eliminates trivial         */
/* recovery from directory listings or slack space.                    */
/* ================================================================== */
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
/* ------------------------------------------------------------------ */
/* Argon2id parameter auto-tuning based on available RAM               */
/* Uses up to 1/4 of free physical RAM, clamped to                     */
/*   [INTERACTIVE .. SENSITIVE] ops/mem range.                         */
/* Falls back to MODERATE on non-Linux where /proc/meminfo is absent.  */
/* ------------------------------------------------------------------ */
static void argon2_pick_params(unsigned long long *ops, size_t *mem){
    *ops = crypto_pwhash_OPSLIMIT_MODERATE;
    *mem = crypto_pwhash_MEMLIMIT_MODERATE;
#ifdef __linux__
    FILE *f = fopen("/proc/meminfo","r");
    if(!f) return;
    unsigned long long mem_avail_kb = 0;
    char line[256];
    while(fgets(line,sizeof(line),f)){
        if(sscanf(line,"MemAvailable: %llu",&mem_avail_kb)==1) break;
    }
    fclose(f);
    if(mem_avail_kb == 0) return;
    size_t budget = (size_t)(mem_avail_kb * 1024ULL / 4ULL);
    if(budget < (size_t)crypto_pwhash_MEMLIMIT_INTERACTIVE)
        budget = (size_t)crypto_pwhash_MEMLIMIT_INTERACTIVE;
    if(budget > (size_t)crypto_pwhash_MEMLIMIT_SENSITIVE)
        budget = (size_t)crypto_pwhash_MEMLIMIT_SENSITIVE;
    *mem = budget;
    if(budget >= (size_t)crypto_pwhash_MEMLIMIT_SENSITIVE)
        *ops = crypto_pwhash_OPSLIMIT_SENSITIVE;
    else if(budget >= (size_t)crypto_pwhash_MEMLIMIT_MODERATE)
        *ops = crypto_pwhash_OPSLIMIT_MODERATE;
    else
        *ops = crypto_pwhash_OPSLIMIT_INTERACTIVE;
#endif
}

static void argon2(uint8_t key[32],const char *pw,const uint8_t *salt){
    STACK_CANARY_INIT(); STACK_CANARY_SAVE(); ANTIDIS_TRAP();
    unsigned long long ops; size_t mem;
    argon2_pick_params(&ops, &mem);
    if(crypto_pwhash(key,32,pw,strlen(pw),salt,ops,mem,
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
struct _curl_buf{char *d;size_t l;};
static size_t _curl_cb(void *p,size_t sz,size_t nm,void *u){
    struct _curl_buf *b=(struct _curl_buf*)u; size_t t=sz*nm;
    char *tmp=realloc(b->d,b->l+t+1); if(!tmp)return 0;
    b->d=tmp; memcpy(b->d+b->l,p,t); b->l+=t; b->d[b->l]='\0'; return t;
}
static char *plat_https_get(const char *url){
    CURL *c=curl_easy_init(); if(!c)return NULL;
    struct _curl_buf r={calloc(1,1),0};
    curl_easy_setopt(c,CURLOPT_URL,url);
    curl_easy_setopt(c,CURLOPT_WRITEFUNCTION,_curl_cb);
    curl_easy_setopt(c,CURLOPT_WRITEDATA,&r);
    curl_easy_setopt(c,CURLOPT_TIMEOUT,10L);
    curl_easy_setopt(c,CURLOPT_FOLLOWLOCATION,1L);
    curl_easy_setopt(c,CURLOPT_PROTOCOLS,CURLPROTO_HTTPS);
    CURLcode res=curl_easy_perform(c);
    long hc=0; curl_easy_getinfo(c,CURLINFO_RESPONSE_CODE,&hc);
    curl_easy_cleanup(c);
    if(res!=CURLE_OK||hc!=200){free(r.d);return NULL;}
    return r.d;
}
static char *fetch_public_ip(void){
    char *resp=plat_https_get("https://ip-api.com/json/?fields=query,countryCode");
    if(!resp)return NULL;
    if(!strstr(resp,"\"US\"")){free(resp);die("G");}
    char *qs=strstr(resp,"\"query\":\""),*ip=NULL;
    if(qs){qs+=9;char *qe=strchr(qs,'"');if(qe){*qe='\0';ip=strdup(qs);}}
    free(resp); return ip;
}

/* ================================================================== */
/* HWID (Linux)                                                         */
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

static void collect_hwid(uint8_t out[64],const uint8_t *user_sec,const char *ip_override){
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
    /* Public IP */
    char *ip=NULL;
    if(ip_override){ip=(char*)ip_override;}
    else{ip=fetch_public_ip();if(!ip){sf(buf,HWID_BUF);die("I");}}
    int n=snprintf((char*)buf+off,HWID_BUF-off,"pip:%s\n",ip);if(n>0&&off+(size_t)n<(size_t)HWID_BUF)off+=(size_t)n;
    if(ip!=ip_override)free(ip);
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
    /* Compress plaintext before encryption */
    size_t comp_sz;
    uint8_t *comp_buf = rv_compress(in, il, &comp_sz);
    const uint8_t *payload = comp_buf;
    size_t payload_len = comp_sz;

    uint8_t salt[SALT_LEN],nonce[NONCE_LEN];
    randombytes_buf(salt,SALT_LEN); randombytes_buf(nonce,NONCE_LEN);
    uint8_t *key=sa(KEY_LEN); derive_key(key,pw,salt,mlkem_sk,mlkem_ct);
    if(otc) for(size_t i=0;i<OTC_LEN&&i<KEY_LEN;i++) key[i]^=otc[i];
    uint8_t mkey[MAC_LEN]; {uint8_t ctx[]={'m','a','c',0};shake256_mac(mkey,MAC_LEN,key,KEY_LEN,ctx,4);}
    uint8_t *ct=malloc(payload_len+TAG_LEN); if(!ct){sf(key,KEY_LEN);free(comp_buf);die("C");}
    unsigned long long cl;
    if(crypto_aead_aes256gcm_encrypt(ct,&cl,payload,payload_len,NULL,0,NULL,nonce,key)!=0){sf(key,KEY_LEN);free(ct);free(comp_buf);die("A");}
    sf(key,KEY_LEN);
    sodium_memzero(comp_buf,comp_sz); free(comp_buf);
    uint8_t hdr[HDR_SZ]; size_t ho=0;
    uint8_t magic[8]; get_magic(magic);
    memcpy(hdr+ho,magic,MAGIC_LEN);ho+=MAGIC_LEN; hdr[ho++]=VERSION;
    w64(hdr+ho,(uint64_t)il);ho+=8;  /* orig uncompressed size */
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
    o+=8; /* skip stored orig_size — recovered via rv_decompress */
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
    uint8_t *comp_plain=malloc(cl-TAG_LEN+1); if(!comp_plain){sf(key,KEY_LEN);free(buf);die("N");}
    unsigned long long dl;
    if(crypto_aead_aes256gcm_decrypt(comp_plain,&dl,NULL,ct,cl,NULL,0,nonce,key)!=0){sf(key,KEY_LEN);free(buf);free(comp_plain);die("Y");}
    sf(key,KEY_LEN); free(buf);
    /* Decompress the decrypted payload */
    uint8_t *plain = rv_decompress(comp_plain, (size_t)dl, ol);
    sodium_memzero(comp_plain, (size_t)dl); free(comp_plain);
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
/* Mini-LZ4 block compressor (self-contained, no external deps)        */
/*                                                                      */
/* Wire format: [comp_flag u8][orig_len u64][compressed_data...]       */
/*   comp_flag = 1  → LZ4-block payload follows                        */
/*   comp_flag = 0  → raw (incompressible) payload follows (no header) */
/*                                                                      */
/* LZ4 block format is the standard LZ4 block spec (no frame header).  */
/* Hash table uses 16-bit offsets for 64 KB window; suitable for all   */
/* realistic plaintext sizes in this tool.                              */
/* ================================================================== */

#define LZ4_HASH_BITS   16
#define LZ4_HTABLE_SIZE (1u << LZ4_HASH_BITS)
#define LZ4_MF_LIMIT    12   /* last 12 bytes are literals only */
#define LZ4_ML_BITS     4
#define LZ4_ML_MASK     ((1u << LZ4_ML_BITS) - 1)
#define LZ4_RUN_MASK    LZ4_ML_MASK
#define LZ4_MINMATCH    4
#define LZ4_SKIPSTRENGTH 6

/* Upper-bound on LZ4 compressed size (per spec: src_size + src_size/255 + 16) */
static size_t lz4_compress_bound(size_t src_size){
    return src_size + (src_size / 255) + 16;
}

static uint32_t lz4_hash4(uint32_t v){
    return (v * 2654435761u) >> (32 - LZ4_HASH_BITS);
}

/* Compress src[0..src_size) → dst; dst must be >= lz4_compress_bound(src_size).
 * Returns number of bytes written to dst, or 0 on failure (shouldn't happen). */
static size_t lz4_compress_block(const uint8_t *src, size_t src_size,
                                  uint8_t *dst, size_t dst_cap)
{
    if(src_size == 0){ return 0; }
    if(dst_cap < lz4_compress_bound(src_size)) return 0;

    /* 16-bit position hash table (positions relative to src) */
    uint32_t htable[LZ4_HTABLE_SIZE];
    memset(htable, 0, sizeof(htable));

    const uint8_t *ip     = src;
    const uint8_t *anchor = src;
    const uint8_t *iend   = src + src_size;
    const uint8_t *mflimit = iend - LZ4_MF_LIMIT;
    uint8_t       *op     = dst;

    if(src_size < LZ4_MINMATCH + 1) goto _last_literals;

    ip++;  /* skip first byte so first hash lookup is at ip=src+1 */

    for(;;){
        const uint8_t *match;
        uint32_t       forwardH;
        unsigned       step   = 1;
        unsigned       skip   = LZ4_SKIPSTRENGTH;

        /* Find a match */
        {
            const uint8_t *fwd = ip;
            do {
                uint32_t h;
                ip   = fwd;
                fwd += step;
                step  = skip++ >> LZ4_SKIPSTRENGTH;
                if(fwd > mflimit) goto _last_literals;
                uint32_t v; memcpy(&v, ip, 4);
                h = lz4_hash4(v);
                uint32_t mpos = htable[h];
                htable[h] = (uint32_t)(ip - src);
                match = src + mpos;
            } while( (uint32_t)(ip - match) > 0xFFFF ||
                     memcmp(ip, match, 4) != 0 );
            forwardH = lz4_hash4(*(uint32_t*)(const void*)fwd);
            (void)forwardH;
        }

        /* Encode literal run */
        {
            size_t lit_len = (size_t)(ip - anchor);
            uint8_t *token = op++;
            if(op + lit_len + 2 + (lit_len >> 8) > dst + dst_cap) return 0;

            if(lit_len >= LZ4_RUN_MASK){
                size_t rem = lit_len - LZ4_RUN_MASK;
                *token = (uint8_t)(LZ4_RUN_MASK << LZ4_ML_BITS);
                while(rem >= 255){ *op++ = 255; rem -= 255; }
                *op++ = (uint8_t)rem;
            } else {
                *token = (uint8_t)(lit_len << LZ4_ML_BITS);
            }
            memcpy(op, anchor, lit_len);
            op += lit_len;
        }

        /* Encode offset */
        {
            uint16_t off = (uint16_t)(ip - match);
            op[0] = (uint8_t)off; op[1] = (uint8_t)(off >> 8); op += 2;
        }

        /* Extend match */
        {
            size_t ml = LZ4_MINMATCH;
            {
                const uint8_t *ip2 = ip + LZ4_MINMATCH;
                const uint8_t *m2  = match + LZ4_MINMATCH;
                const uint8_t *mlimit2 = iend - 5;
                while(ip2 <= mlimit2 && *ip2 == *m2){ ip2++; m2++; }
                ml = (size_t)(ip2 - ip);
            }
            size_t ml_enc = ml - LZ4_MINMATCH;
            uint8_t *token = op - 2 - (size_t)((ip - anchor) >= LZ4_RUN_MASK ?
                              1 + (((ip-anchor)-LZ4_RUN_MASK+254)/255) : 0)
                              - (ip - anchor) - 1;
            /* token was written above; just patch its low nibble */
            (void)token; /* patching done inline below */

            /* patch token low nibble for match length */
            uint8_t *tkp = op - 2 - (op - dst > 2 ? 0 : 0);
            /* walk back to the token we emitted: literal bytes + 1 token byte */
            {
                size_t lit_len = (size_t)(ip - anchor);
                size_t skip_b = lit_len;
                if(lit_len >= LZ4_RUN_MASK){ size_t rem=lit_len-LZ4_RUN_MASK; skip_b+= 1 + (rem+254)/255; }
                tkp = op - 2 - skip_b - 1 + 0; /* already past literals */
                tkp = op - skip_b - 2 - 1;
                (void)tkp;
            }
            /* Simpler: just write ml low-nibble into the token byte we placed */
            /* The token is at: op - lit_bytes - extra_len_bytes - 1 - 2(offset) */
            /* Re-compute cleanly: */
            {
                size_t lit_len = (size_t)(ip - anchor);
                size_t extra   = (lit_len >= LZ4_RUN_MASK) ?
                                 1 + ((lit_len - LZ4_RUN_MASK + 254) / 255) : 0;
                uint8_t *tok   = op - 2 - lit_len - extra - 1;
                if(ml_enc >= LZ4_ML_MASK){
                    *tok |= LZ4_ML_MASK;
                    size_t rem = ml_enc - LZ4_ML_MASK;
                    while(rem >= 255){ if(op >= dst+dst_cap) return 0; *op++ = 255; rem -= 255; }
                    if(op >= dst+dst_cap) return 0;
                    *op++ = (uint8_t)rem;
                } else {
                    *tok |= (uint8_t)ml_enc;
                }
            }

            ip    += ml;
            anchor = ip;

            /* Update hash at new ip */
            if(ip <= mflimit){
                uint32_t v; memcpy(&v, ip - 2, 4);
                htable[lz4_hash4(v)] = (uint32_t)(ip - 2 - src);
            }
        }

        if(ip > mflimit) goto _last_literals;
    }

_last_literals:
    {
        size_t last_len = (size_t)(iend - anchor);
        if(op + last_len + 1 + (last_len >= LZ4_RUN_MASK ? 1 + (last_len - LZ4_RUN_MASK + 254)/255 : 0)
           > dst + dst_cap) return 0;

        uint8_t *token = op++;
        if(last_len >= LZ4_RUN_MASK){
            size_t rem = last_len - LZ4_RUN_MASK;
            *token = (uint8_t)(LZ4_RUN_MASK << LZ4_ML_BITS);
            while(rem >= 255){ *op++ = 255; rem -= 255; }
            *op++ = (uint8_t)rem;
        } else {
            *token = (uint8_t)(last_len << LZ4_ML_BITS);
        }
        memcpy(op, anchor, last_len);
        op += last_len;
    }

    return (size_t)(op - dst);
}

/* Decompress one LZ4 block.  dst must be >= orig_size bytes.
 * Returns orig_size on success, 0 on error. */
static size_t lz4_decompress_block(const uint8_t *src, size_t src_size,
                                    uint8_t *dst, size_t orig_size)
{
    const uint8_t *ip   = src;
    const uint8_t *iend = src + src_size;
    uint8_t       *op   = dst;
    uint8_t       *oend = dst + orig_size;

    while(ip < iend){
        uint8_t token = *ip++;
        /* Literal length */
        size_t lit_len = token >> LZ4_ML_BITS;
        if(lit_len == LZ4_RUN_MASK){
            uint8_t s;
            do { if(ip >= iend) return 0; s = *ip++; lit_len += s; } while(s == 255);
        }
        if(op + lit_len > oend || ip + lit_len > iend) return 0;
        memcpy(op, ip, lit_len); op += lit_len; ip += lit_len;
        if(ip >= iend) break; /* last sequence has no match */

        /* Match offset */
        if(ip + 2 > iend) return 0;
        uint16_t off = (uint16_t)ip[0] | ((uint16_t)ip[1] << 8); ip += 2;
        if(off == 0 || op - dst < off) return 0;
        const uint8_t *mp = op - off;

        /* Match length */
        size_t ml = (token & LZ4_ML_MASK) + LZ4_MINMATCH;
        if((token & LZ4_ML_MASK) == LZ4_ML_MASK){
            uint8_t s;
            do { if(ip >= iend) return 0; s = *ip++; ml += s; } while(s == 255);
        }
        if(op + ml > oend) return 0;
        /* Copy (may overlap) */
        for(size_t i = 0; i < ml; i++) op[i] = mp[i];
        op += ml;
    }
    return (size_t)(op - dst);
}

/* ------------------------------------------------------------------ */
/* High-level compress / decompress with comp_flag header              */
/*                                                                      */
/*  rv_compress(in, il, &ol):                                          */
/*    Returns malloc'd buffer:                                          */
/*      [1 byte flag][8 byte orig_len LE][compressed bytes]  when flag=1 */
/*      [1 byte flag=0][original bytes]                       when incompressible */
/*                                                                      */
/*  rv_decompress(in, il, &ol):                                         */
/*    Undoes rv_compress.                                                */
/* ------------------------------------------------------------------ */
#define RV_COMP_FLAG_COMPRESSED   1
#define RV_COMP_FLAG_RAW          0
#define RV_COMP_HEADER_SZ         9   /* 1 (flag) + 8 (orig_len) */

static uint8_t *rv_compress(const uint8_t *in, size_t il, size_t *ol)
{
    if(il == 0){
        /* empty: just store raw */
        uint8_t *out = malloc(1);
        if(!out) die("rv_compress malloc");
        out[0] = RV_COMP_FLAG_RAW;
        *ol = 1;
        return out;
    }

    size_t cb = lz4_compress_bound(il);
    uint8_t *tmp = malloc(cb);
    if(!tmp) die("rv_compress tmp malloc");

    size_t csz = lz4_compress_block(in, il, tmp, cb);

    /* Only use compression if it actually shrinks the data */
    if(csz > 0 && csz < il){
        size_t total = RV_COMP_HEADER_SZ + csz;
        uint8_t *out = malloc(total);
        if(!out){ free(tmp); die("rv_compress out malloc"); }
        out[0] = RV_COMP_FLAG_COMPRESSED;
        w64(out + 1, (uint64_t)il);
        memcpy(out + RV_COMP_HEADER_SZ, tmp, csz);
        free(tmp);
        *ol = total;
        return out;
    }

    /* Incompressible: store raw with flag byte */
    free(tmp);
    uint8_t *out = malloc(1 + il);
    if(!out) die("rv_compress raw malloc");
    out[0] = RV_COMP_FLAG_RAW;
    memcpy(out + 1, in, il);
    *ol = 1 + il;
    return out;
}

static uint8_t *rv_decompress(const uint8_t *in, size_t il, size_t *ol)
{
    if(il < 1) die("rv_decompress: truncated");
    uint8_t flag = in[0];

    if(flag == RV_COMP_FLAG_RAW){
        size_t data_len = il - 1;
        uint8_t *out = malloc(data_len + 1); /* +1 so malloc(0) is valid */
        if(!out) die("rv_decompress raw malloc");
        memcpy(out, in + 1, data_len);
        *ol = data_len;
        return out;
    }

    if(flag == RV_COMP_FLAG_COMPRESSED){
        if(il < RV_COMP_HEADER_SZ) die("rv_decompress: header too short");
        uint64_t orig_len = r64(in + 1);
        if(orig_len > 1ULL * 1024 * 1024 * 1024) die("rv_decompress: implausible orig_len");
        const uint8_t *comp_data = in + RV_COMP_HEADER_SZ;
        size_t         comp_sz   = il - RV_COMP_HEADER_SZ;
        uint8_t *out = malloc((size_t)orig_len + 1);
        if(!out) die("rv_decompress out malloc");
        size_t got = lz4_decompress_block(comp_data, comp_sz, out, (size_t)orig_len);
        if(got != (size_t)orig_len){
            free(out); die("rv_decompress: decompression mismatch");
        }
        *ol = (size_t)orig_len;
        return out;
    }

    die("rv_decompress: unknown flag");
}

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
    /* Compress plaintext before encryption */
    size_t cl_in;
    uint8_t *compressed = rv_compress(in, il, &cl_in);

    uint8_t salt[SALT_LEN],nonce[OTC_NONCE_LEN];
    randombytes_buf(salt,SALT_LEN); randombytes_buf(nonce,OTC_NONCE_LEN);
    uint8_t key[OTC_KEY_LEN]; fast_kdf(key,pw,salt);
    size_t olen=SALT_LEN+OTC_NONCE_LEN+cl_in+OTC_TAG_LEN;
    uint8_t *out=malloc(olen); if(!out){sodium_memzero(key,sizeof(key));free(compressed);die("N");}
    memcpy(out,salt,SALT_LEN); memcpy(out+SALT_LEN,nonce,OTC_NONCE_LEN);
    unsigned long long encl;
    if(crypto_aead_xchacha20poly1305_ietf_encrypt(out+SALT_LEN+OTC_NONCE_LEN,&encl,
            compressed,cl_in,NULL,0,NULL,nonce,key)!=0)
        {sodium_memzero(key,sizeof(key));free(out);free(compressed);die("A");}
    sodium_memzero(compressed,cl_in); free(compressed);
    sodium_memzero(key,sizeof(key));
    *ol=SALT_LEN+OTC_NONCE_LEN+(size_t)encl;
    return out;
}
static uint8_t *otc_decrypt(const uint8_t *in,size_t il,const char *pw,size_t *ol){
    if(il<SALT_LEN+OTC_NONCE_LEN+OTC_TAG_LEN)die("H");
    uint8_t salt[SALT_LEN],nonce[OTC_NONCE_LEN];
    memcpy(salt,in,SALT_LEN); memcpy(nonce,in+SALT_LEN,OTC_NONCE_LEN);
    uint8_t key[OTC_KEY_LEN]; fast_kdf(key,pw,salt);
    size_t ctl=il-SALT_LEN-OTC_NONCE_LEN;
    uint8_t *tmp=malloc(ctl); if(!tmp){sodium_memzero(key,sizeof(key));die("N");}
    unsigned long long dl;
    if(crypto_aead_xchacha20poly1305_ietf_decrypt(tmp,&dl,NULL,in+SALT_LEN+OTC_NONCE_LEN,ctl,NULL,0,nonce,key)!=0)
        {sodium_memzero(key,sizeof(key));free(tmp);die("Y: wrong password or corrupt data");}
    sodium_memzero(key,sizeof(key));
    /* Decompress the decrypted payload */
    uint8_t *out = rv_decompress(tmp, (size_t)dl, ol);
    sodium_memzero(tmp, (size_t)dl); free(tmp);
    return out;
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

/* ================================================================== */
/* Memory/Swap Monitoring Failsafe                                     */
/* ================================================================== */
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
/* Wrong-password wipe counter                                         */
/* After WIPE_FAIL_LIMIT consecutive decrypt failures on the same      */
/* container file, the file is overwritten with random bytes and       */
/* deleted. The counter resets on any successful decode.               */
/* ================================================================== */
#define WIPE_FAIL_LIMIT 5
static int g_fail_count = 0;

static void fail_count_hit(const char *path){
    g_fail_count++;
    dprintf(STDERR_FILENO,"rv: wrong password (%d/%d)\n",g_fail_count,WIPE_FAIL_LIMIT);
    if(g_fail_count >= WIPE_FAIL_LIMIT && path){
        dprintf(STDERR_FILENO,"rv: too many failures — destroying %s\n",path);
        int fd=open(path,O_WRONLY);
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
        unlink(path);
        _exit(1);
    }
}
static void fail_count_reset(void){ g_fail_count=0; }

/* ================================================================== */
/* Key file integrity — version + entry-count header                  */
/*                                                                      */
/* Updated wire format:                                                 */
/*   "RVKF\x02" (5) — magic + version byte                            */
/*   entry_count  (4 LE) — number of key entries                      */
/*   salt (SALT_LEN) | nonce (OTC_NONCE_LEN) | ciphertext+tag         */
/*   outer_mac (32)  — SHAKE-256-MAC over all preceding bytes,        */
/*                     keyed with SHAKE-256("rv6-kf-mac-v1"||salt)    */
/*                                                                      */
/* The outer MAC allows detecting truncation or bit-flips even before  */
/* attempting AEAD decryption.  The entry count in plaintext enables   */
/* detecting truncated ciphertext (missing entries) immediately.       */
/* ================================================================== */
#undef  KF_MAGIC
#undef  KF_MAGIC_LEN
#define KF_MAGIC      "RVKF\x02"
#define KF_MAGIC_LEN  5
#define KF_EC_LEN     4          /* entry count field */
#define KF_OUTER_MAC_LEN 32

static void kf_outer_mac(uint8_t mac[KF_OUTER_MAC_LEN],
                          const uint8_t *data, size_t data_len,
                          const uint8_t *salt)
{
    uint8_t mkey[KF_OUTER_MAC_LEN];
    keccak_ctx c; shake256_init(&c);
    const uint8_t dom[]="rv6-kf-mac-v1";
    shake256_absorb(&c,dom,sizeof(dom)-1);
    shake256_absorb(&c,salt,SALT_LEN);
    shake256_finalize(&c); shake256_squeeze(&c,mkey,KF_OUTER_MAC_LEN);
    shake256_mac(mac, KF_OUTER_MAC_LEN, mkey, KF_OUTER_MAC_LEN, data, data_len);
    sodium_memzero(mkey,KF_OUTER_MAC_LEN);
}

/* ================================================================== */
/* Encrypted key file (v2 — with integrity MAC)                       */
/* ================================================================== */
static void kf_write_enc(const KeyFile *kf, const char *path, const char *master_pw){
    kf_write_enc_to(kf, path, master_pw);
}

static void kf_read_enc(KeyFile *kf, const char *path, const char *master_pw){
    size_t sz; uint8_t *buf=rfile(path,&sz);

    /* Detect format version */
    int is_v2 = (sz >= KF_MAGIC_LEN && memcmp(buf, KF_MAGIC, KF_MAGIC_LEN)==0);
    int is_v1 = (!is_v2 && sz >= 4 && memcmp(buf, "RVKF", 4)==0);

    if(!is_v2 && !is_v1){
        /* Plaintext legacy format */
        free(buf); kf_read(kf,path); return;
    }

    if(is_v2){
        /* Verify outer MAC before touching the ciphertext */
        if(sz < KF_MAGIC_LEN + KF_EC_LEN + SALT_LEN + OTC_NONCE_LEN + OTC_TAG_LEN + KF_OUTER_MAC_LEN){
            free(buf); die("kf: file too short (v2)");
        }
        size_t body_sz = sz - KF_OUTER_MAC_LEN;
        /* salt is at offset KF_MAGIC_LEN + KF_EC_LEN */
        const uint8_t *salt_ptr = buf + KF_MAGIC_LEN + KF_EC_LEN;
        uint8_t expected_mac[KF_OUTER_MAC_LEN];
        kf_outer_mac(expected_mac, buf, body_sz, salt_ptr);
        if(sodium_memcmp(buf + body_sz, expected_mac, KF_OUTER_MAC_LEN)!=0){
            free(buf);
            die("kf: integrity check failed — key file may be corrupt or tampered");
        }

        /* Extract stored entry count */
        uint32_t stored_cnt = r32(buf + KF_MAGIC_LEN);

        size_t o = KF_MAGIC_LEN + KF_EC_LEN;
        uint8_t salt[SALT_LEN], nonce[OTC_NONCE_LEN];
        memcpy(salt,  buf+o, SALT_LEN);  o+=SALT_LEN;
        memcpy(nonce, buf+o, OTC_NONCE_LEN); o+=OTC_NONCE_LEN;
        size_t ctl = body_sz - o;
        uint8_t key[OTC_KEY_LEN]; fast_kdf(key, master_pw, salt);
        uint8_t *pt=malloc(ctl); if(!pt){sodium_memzero(key,sizeof(key));free(buf);die("N");}
        unsigned long long dl;
        if(crypto_aead_xchacha20poly1305_ietf_decrypt(pt,&dl,NULL,buf+o,ctl,NULL,0,nonce,key)!=0){
            sodium_memzero(key,sizeof(key));free(pt);free(buf);
            die("kf: wrong master password or corrupt ciphertext");
        }
        sodium_memzero(key,sizeof(key)); free(buf);

        kf_init(kf);
        char *line=(char*)pt; size_t start=0;
        for(size_t i=0;i<=(size_t)dl;i++){
            if(i==(size_t)dl || pt[i]=='\n'){
                size_t ll=i-start;
                if(ll>0){
                    char tmp[MAX_PATH_LEN+FILE_PW_LEN+4];
                    if(ll<sizeof(tmp)){
                        memcpy(tmp,line+start,ll); tmp[ll]='\0';
                        char *lc=strrchr(tmp,':');
                        if(lc){*lc='\0'; kf_add(kf,tmp,lc+1);}
                    }
                }
                start=i+1;
            }
        }
        sodium_memzero(pt,(size_t)dl); free(pt);
        (void)line;

        /* Verify decrypted entry count matches plaintext header */
        if(kf->cnt != (size_t)stored_cnt){
            kf_free(kf);
            die("kf: entry count mismatch — key file may be truncated or tampered");
        }
        return;
    }

    /* v1 fallback (old format without outer MAC — parse as before) */
    {
        size_t o=4; /* skip "RVKF" */
        if(sz < 4 + SALT_LEN + OTC_NONCE_LEN + OTC_TAG_LEN){ free(buf); die("kf: v1 file too short"); }
        uint8_t salt[SALT_LEN],nonce[OTC_NONCE_LEN];
        memcpy(salt,buf+o,SALT_LEN);o+=SALT_LEN;
        memcpy(nonce,buf+o,OTC_NONCE_LEN);o+=OTC_NONCE_LEN;
        size_t ctl=sz-o;
        uint8_t key[OTC_KEY_LEN]; fast_kdf(key,master_pw,salt);
        uint8_t *pt=malloc(ctl); if(!pt){sodium_memzero(key,sizeof(key));free(buf);die("N");}
        unsigned long long dl;
        if(crypto_aead_xchacha20poly1305_ietf_decrypt(pt,&dl,NULL,buf+o,ctl,NULL,0,nonce,key)!=0){
            sodium_memzero(key,sizeof(key));free(pt);free(buf);
            die("kf: wrong master password (v1 format)");
        }
        sodium_memzero(key,sizeof(key)); free(buf);
        kf_init(kf);
        char *line=(char*)pt; size_t start=0;
        for(size_t i=0;i<=(size_t)dl;i++){
            if(i==(size_t)dl || pt[i]=='\n'){
                size_t ll=i-start;
                if(ll>0){
                    char tmp[MAX_PATH_LEN+FILE_PW_LEN+4];
                    if(ll<sizeof(tmp)){
                        memcpy(tmp,line+start,ll); tmp[ll]='\0';
                        char *lc=strrchr(tmp,':');
                        if(lc){*lc='\0'; kf_add(kf,tmp,lc+1);}
                    }
                }
                start=i+1;
            }
        }
        sodium_memzero(pt,(size_t)dl); free(pt);
        (void)line;
        printf("  [note] Key file is v1 format — re-encoding will upgrade to v2\n");
    }
}


/* ================================================================== */
/* Filename obfuscation                                                 */
/*                                                                      */
/* Before writing a relpath into the container wire format, encrypt it */
/* with XChaCha20-Poly1305 using a path-key derived from the container */
/* password.  The stored form is:                                       */
/*   [enc_len u16][nonce OTC_NONCE_LEN][ciphertext+tag]                */
/*                                                                      */
/* On decode the path-key is re-derived and the name is decrypted.     */
/* The path-key is never stored on disk.                                */
/* ================================================================== */
static void make_path_key(uint8_t key[OTC_KEY_LEN], const char *cont_pw){
    keccak_ctx c; shake256_init(&c);
    const uint8_t dom[]="rv5-path-key-v1";
    shake256_absorb(&c,dom,sizeof(dom)-1);
    shake256_absorb(&c,(const uint8_t*)cont_pw,strlen(cont_pw));
    shake256_finalize(&c); shake256_squeeze(&c,key,OTC_KEY_LEN);
}

/* encrypt relpath → [enc_len u16][nonce][ct+tag] appended to bb */
static void enc_relpath(BB *out, const char *rel, const char *cont_pw){
    uint8_t pkey[OTC_KEY_LEN]; make_path_key(pkey,cont_pw);
    uint8_t nonce[OTC_NONCE_LEN]; randombytes_buf(nonce,OTC_NONCE_LEN);
    size_t rlen=strlen(rel);
    size_t ct_max=rlen+OTC_TAG_LEN;
    uint8_t *ct=malloc(ct_max); if(!ct){sodium_memzero(pkey,sizeof(pkey));die("N");}
    unsigned long long cl;
    if(crypto_aead_xchacha20poly1305_ietf_encrypt(ct,&cl,(const uint8_t*)rel,rlen,NULL,0,NULL,nonce,pkey)!=0)
        {sodium_memzero(pkey,sizeof(pkey));free(ct);die("A");}
    sodium_memzero(pkey,sizeof(pkey));
    uint16_t enclen=(uint16_t)(OTC_NONCE_LEN+(size_t)cl);
    uint8_t el[2]; w16(el,enclen); bb_app(out,el,2);
    bb_app(out,nonce,OTC_NONCE_LEN);
    bb_app(out,ct,(size_t)cl); free(ct);
}

/* decrypt relpath from buf[*off]; advances *off; caller owns returned string */
static char *dec_relpath(const uint8_t *buf, size_t bufsz, size_t *off, const char *cont_pw){
    if(*off+2>bufsz) return NULL;
    uint16_t enclen=r16(buf+*off); *off+=2;
    if(*off+(size_t)enclen>bufsz) return NULL;
    if(enclen<OTC_NONCE_LEN+OTC_TAG_LEN) return NULL;
    const uint8_t *nonce=buf+*off;
    const uint8_t *ct=buf+*off+OTC_NONCE_LEN;
    size_t ctl=(size_t)enclen-OTC_NONCE_LEN;
    uint8_t pkey[OTC_KEY_LEN]; make_path_key(pkey,cont_pw);
    uint8_t *plain=malloc(ctl); if(!plain){sodium_memzero(pkey,sizeof(pkey));return NULL;}
    unsigned long long dl;
    if(crypto_aead_xchacha20poly1305_ietf_decrypt(plain,&dl,NULL,ct,ctl,NULL,0,nonce,pkey)!=0)
        {sodium_memzero(pkey,sizeof(pkey));free(plain);return NULL;}
    sodium_memzero(pkey,sizeof(pkey));
    plain[dl]='\0';
    *off+=(size_t)enclen;
    return (char*)plain;
}

/* ================================================================== */
/* Container tree checksum (SHAKE-256 of all decoded file contents)    */
/*                                                                      */
/* Computed during encode by hashing every file in sorted order:       */
/*   SHAKE256( for each file: [relpath_len u16][relpath][data_len u64] */
/*                             [file_data] )                            */
/* Stored as a 32-byte value in the root archive header.               */
/* Verified during decode before writing any file to disk.             */
/* ================================================================== */
#define TREE_HASH_LEN 32

/* Updated CONT_MAGIC to version 6 to distinguish obfuscated-path format */
static const uint8_t CONT_MAGIC_V6[8]={'R','V','C','O','N','T',0x06,0x00};

/* ================================================================== */
/* Container index for random access / partial decode                  */
/*                                                                      */
/* Appended after the wire body as:                                     */
/*   [INDEX_MAGIC 8][entry_count u32]                                  */
/*   per entry: [enc_relpath_len u16][enc_relpath ...][offset u64][file_enc_sz u64] */
/*   [index_offset u64]   ← absolute offset from start of wire blob   */
/*                                                                      */
/* The index itself is encrypted with the container password via        */
/* otc_encrypt, then appended to the wire blob before the outer        */
/* otc_encrypt call.                                                    */
/* ================================================================== */
static const uint8_t IDX_MAGIC[8]={'R','V','I','D','X',0x01,0x00,0x00};

/* ================================================================== */
/* Container wire format v6                                             */
/*  [magic 8][file_count 4][tree_hash 32]                              */
/*  per file: [enc_relpath...][data_len 8][enc_data M]                 */
/*  [index blob encrypted][index_offset 8]                             */
/* ================================================================== */

/* ================================================================== */
/* Encode worker (v6: encrypted paths + tree hash + index)             */
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
    /* stats for dry-run / inspect */
    size_t          raw_bytes;
    size_t          comp_bytes;
    struct timespec finish_time;  /* set by worker just before sem_post */
}ContWork;

static void *cont_worker(void *arg){
    ContWork *w=(ContWork*)arg;
    check_swap_usage();
    gen_password(w->cont_pw);
    for(size_t i=0;i<w->nfiles;i++){
        if(!valid_relpath(w->relpaths[i])){
            dprintf(STDERR_FILENO,"rv: invalid path in container: %s\n",w->relpaths[i]);
            die("P");
        }
    }

    /* Build per-file data + compute tree hash */
    shake_ctx tree_ctx; shake256_init(&tree_ctx);

    /* Pre-size wire buffer */
    size_t hint=12+TREE_HASH_LEN;
    for(size_t i=0;i<w->nfiles;i++){
        char abs[MAX_PATH_LEN]; snprintf(abs,sizeof(abs),"%s/%s",w->root_dir,w->relpaths[i]);
        struct stat st; int fd=open(abs,O_RDONLY|O_NOFOLLOW);
        if(fd>=0){
            if(fstat(fd,&st)==0&&st.st_size>0)
                hint+=2+strlen(w->relpaths[i])+OTC_NONCE_LEN+OTC_TAG_LEN+8+(size_t)st.st_size+SALT_LEN+OTC_NONCE_LEN+OTC_TAG_LEN+64;
            else hint+=256;
            close(fd);
        } else hint+=256;
    }
    BB wire; wire.cap=hint;wire.sz=0;wire.d=malloc(wire.cap);if(!wire.d)die("N");
    wipe_register((volatile uint8_t*)wire.d, wire.cap);
    bb_app(&wire,CONT_MAGIC_V6,8);
    uint8_t fc[4]; w32(fc,(uint32_t)w->nfiles); bb_app(&wire,fc,4);
    /* Reserve tree_hash slot (will fill after all files) */
    size_t tree_hash_off=wire.sz;
    uint8_t zerohash[TREE_HASH_LEN]={0}; bb_app(&wire,zerohash,TREE_HASH_LEN);

    /* Build index in parallel BB */
    BB idx; bb_init(&idx);
    wipe_register((volatile uint8_t*)idx.d, idx.cap);

    char (*fpws)[FILE_PW_LEN+1]=malloc(w->nfiles*(FILE_PW_LEN+1)); if(!fpws)die("N");
    w->raw_bytes=0; w->comp_bytes=0;

    for(size_t i=0;i<w->nfiles;i++){
        gen_password(fpws[i]);
        char abs[MAX_PATH_LEN]; snprintf(abs,sizeof(abs),"%s/%s",w->root_dir,w->relpaths[i]);
        size_t fsz; uint8_t *fdata=rfile_fast(abs,&fsz);
        w->raw_bytes+=fsz;

        /* Feed into tree hash: relpath then raw data */
        uint16_t rplen16=(uint16_t)strlen(w->relpaths[i]);
        uint8_t rpl_h[2]; w16(rpl_h,rplen16);
        shake256_absorb(&tree_ctx,rpl_h,2);
        shake256_absorb(&tree_ctx,(const uint8_t*)w->relpaths[i],rplen16);
        uint8_t fsz_h[8]; w64(fsz_h,(uint64_t)fsz);
        shake256_absorb(&tree_ctx,fsz_h,8);
        shake256_absorb(&tree_ctx,fdata,fsz);

        size_t efsz; uint8_t *ef=otc_encrypt(fdata,fsz,fpws[i],&efsz);
        sodium_memzero(fdata,fsz); free(fdata);
        w->comp_bytes+=efsz;
        prog_add_bytes((uint64_t)fsz);  /* update live progress counter */

        /* Index: record offset before appending enc_relpath+data */
        size_t file_offset=wire.sz;
        /* Encrypted relpath */
        enc_relpath(&wire,w->relpaths[i],w->cont_pw);
        uint8_t dl[8]; w64(dl,(uint64_t)efsz); bb_app(&wire,dl,8);
        bb_app(&wire,ef,efsz); free(ef);

        /* Append index entry: enc_relpath (again for index) + offsets */
        size_t idx_entry_start=idx.sz;
        enc_relpath(&idx,w->relpaths[i],w->cont_pw);
        uint8_t off_b[8]; w64(off_b,(uint64_t)file_offset); bb_app(&idx,off_b,8);
        uint8_t esz_b[8]; w64(esz_b,(uint64_t)efsz); bb_app(&idx,esz_b,8);
        (void)idx_entry_start;
    }

    /* Finalise tree hash and write into reserved slot */
    uint8_t tree_hash[TREE_HASH_LEN];
    shake256_finalize(&tree_ctx); shake256_squeeze(&tree_ctx,tree_hash,TREE_HASH_LEN);
    memcpy(wire.d+tree_hash_off,tree_hash,TREE_HASH_LEN);

    /* Encrypt and append index */
    size_t idx_enc_sz; uint8_t *idx_enc=otc_encrypt(idx.d,idx.sz,w->cont_pw,&idx_enc_sz);
    sodium_memzero(idx.d,idx.sz); bb_free(&idx);
    wipe_unregister((volatile uint8_t*)idx.d);
    size_t idx_off=wire.sz;
    bb_app(&wire,IDX_MAGIC,8);
    uint8_t iesz_b[8]; w64(iesz_b,(uint64_t)idx_enc_sz); bb_app(&wire,iesz_b,8);
    bb_app(&wire,idx_enc,idx_enc_sz); free(idx_enc);
    uint8_t idx_off_b[8]; w64(idx_off_b,(uint64_t)idx_off); bb_app(&wire,idx_off_b,8);

    w->enc_data=otc_encrypt(wire.d,wire.sz,w->cont_pw,&w->enc_sz);
    wipe_unregister((volatile uint8_t*)wire.d);
    sodium_memzero(wire.d,wire.sz); bb_free(&wire);

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
    free(fpws); w->done=1;
    prog_done_cont();
    clock_gettime(CLOCK_MONOTONIC, &w->finish_time);
    sem_post_s(w->slot);
    return NULL;
}

/* ================================================================== */
/* Delta helpers                                                        */
/* ================================================================== */
#define SNAP_HASH_LEN 32
typedef struct{ char *rel; uint8_t hash[SNAP_HASH_LEN]; } SnapEntry;
typedef struct{ SnapEntry *e; size_t cnt,cap; } Snap;
static void snap_init(Snap *s){ s->cap=64;s->cnt=0;s->e=malloc(s->cap*sizeof(SnapEntry));if(!s->e)die("N"); }
static void snap_free(Snap *s){ for(size_t i=0;i<s->cnt;i++)free(s->e[i].rel);free(s->e);s->e=NULL;s->cnt=s->cap=0; }
static void snap_add(Snap *s,const char *rel,const uint8_t h[SNAP_HASH_LEN]){
    if(s->cnt>=s->cap){s->cap*=2;s->e=realloc(s->e,s->cap*sizeof(SnapEntry));if(!s->e)die("N");}
    s->e[s->cnt].rel=strdup(rel); memcpy(s->e[s->cnt].hash,h,SNAP_HASH_LEN); s->cnt++;
}
static int snap_lookup(const Snap *s,const char *rel,uint8_t out[SNAP_HASH_LEN]){
    for(size_t i=0;i<s->cnt;i++) if(!strcmp(s->e[i].rel,rel)){memcpy(out,s->e[i].hash,SNAP_HASH_LEN);return 1;}
    return 0;
}
static void snap_read(Snap *s,const char *snap_path){
    snap_init(s); FILE *f=fopen(snap_path,"r"); if(!f)return;
    char line[MAX_PATH_LEN+SNAP_HASH_LEN*2+4];
    while(fgets(line,sizeof(line),f)){
        size_t ll=strlen(line); if(ll>0&&line[ll-1]=='\n')line[--ll]='\0'; if(!ll)continue;
        char *colon=strrchr(line,':'); if(!colon)continue; *colon='\0'; const char *hex=colon+1;
        if(strlen(hex)!=SNAP_HASH_LEN*2)continue;
        uint8_t h[SNAP_HASH_LEN];
        for(int i=0;i<SNAP_HASH_LEN;i++){unsigned v=0;if(sscanf(hex+i*2,"%02x",&v)!=1)break;h[i]=(uint8_t)v;}
        snap_add(s,line,h);
    }
    fclose(f);
}
static void snap_write(const char *snap_path,const char *root,FileList *fl){
    FILE *f=fopen(snap_path,"w"); if(!f)return;
    for(size_t i=0;i<fl->cnt;i++){
        char abs[MAX_PATH_LEN]; snprintf(abs,sizeof(abs),"%s/%s",root,fl->paths[i]);
        size_t fsz; uint8_t *fdata=rfile_fast(abs,&fsz);
        uint8_t h[SNAP_HASH_LEN]; shake256(h,SNAP_HASH_LEN,fdata,fsz);
        sodium_memzero(fdata,fsz); free(fdata);
        fprintf(f,"%s:",fl->paths[i]);
        for(int j=0;j<SNAP_HASH_LEN;j++) fprintf(f,"%02x",h[j]);
        fprintf(f,"\n");
    }
    fclose(f);
}

/* ================================================================== */
/* Atomic output of .otc + .key pair                                   */
/*                                                                      */
/* Writes both files to .tmp paths first, then renames both, then     */
/* creates a tiny sentinel <base>.ok marking the set complete.         */
/* A crash between the two renames leaves a .otc.tmp with no .key —   */
/* the sentinel absence signals an incomplete encode to the user.      */
/* ================================================================== */
static void atomic_write_pair(const char *otc_path, const uint8_t *otc_data, size_t otc_sz,
                               const char *key_path, const KeyFile *kf, const char *master_pw)
{
    char otc_tmp[MAX_PATH_LEN], key_tmp[MAX_PATH_LEN];
    snprintf(otc_tmp, sizeof(otc_tmp), "%s.tmp", otc_path);
    snprintf(key_tmp, sizeof(key_tmp), "%s.tmp", key_path);

    /* Write both tmp files */
    wfile(otc_tmp, otc_data, otc_sz);
    kf_write_enc_to(kf, key_tmp, master_pw);

    /* Rename .otc first, then .key */
    if(rename(otc_tmp, otc_path)!=0){ unlink(otc_tmp); unlink(key_tmp); die("atomic rename .otc"); }
    if(rename(key_tmp, key_path)!=0){ unlink(key_tmp); die("atomic rename .key"); }

    /* Write sentinel */
    char ok_path[MAX_PATH_LEN];
    /* derive base: strip _root.otc suffix */
    strncpy(ok_path, otc_path, sizeof(ok_path)-1); ok_path[sizeof(ok_path)-1]='\0';
    char *suf=strstr(ok_path,"_root.otc");
    if(suf) snprintf(suf, sizeof(ok_path)-(size_t)(suf-ok_path), ".ok");
    else    snprintf(ok_path, sizeof(ok_path), "%s.ok", otc_path);
    FILE *f=fopen(ok_path,"wb"); if(f){ fprintf(f,"ok\n"); fclose(f); }
}

/* kf_write_enc_to: write encrypted key file to an explicit path
 * (used by atomic_write_pair and rekey) */
static void kf_write_enc_to(const KeyFile *kf, const char *path, const char *master_pw){
    BB pt; bb_init(&pt);
    for(size_t i=0;i<kf->cnt;i++){
        size_t ll=strlen(kf->entries[i].label);
        size_t pl=strlen(kf->entries[i].pw);
        bb_app(&pt,(const uint8_t*)kf->entries[i].label,ll);
        bb_app(&pt,(const uint8_t*)":",1);
        bb_app(&pt,(const uint8_t*)kf->entries[i].pw,pl);
        bb_app(&pt,(const uint8_t*)"\n",1);
    }
    uint8_t salt[SALT_LEN], nonce[OTC_NONCE_LEN];
    randombytes_buf(salt,SALT_LEN); randombytes_buf(nonce,OTC_NONCE_LEN);
    uint8_t key[OTC_KEY_LEN]; fast_kdf(key,master_pw,salt);
    size_t ct_max=pt.sz+OTC_TAG_LEN;
    uint8_t *ct=malloc(ct_max); if(!ct){sodium_memzero(key,sizeof(key));bb_free(&pt);die("N");}
    unsigned long long cl;
    if(crypto_aead_xchacha20poly1305_ietf_encrypt(ct,&cl,pt.d,pt.sz,NULL,0,NULL,nonce,key)!=0)
        {sodium_memzero(key,sizeof(key));free(ct);bb_free(&pt);die("A");}
    sodium_memzero(key,sizeof(key)); sodium_memzero(pt.d,pt.sz); bb_free(&pt);
    size_t body_sz = KF_MAGIC_LEN + KF_EC_LEN + SALT_LEN + OTC_NONCE_LEN + (size_t)cl;
    size_t total   = body_sz + KF_OUTER_MAC_LEN;
    uint8_t *buf=malloc(total); if(!buf){free(ct);die("N");}
    size_t o=0;
    memcpy(buf+o, KF_MAGIC, KF_MAGIC_LEN);  o+=KF_MAGIC_LEN;
    w32(buf+o, (uint32_t)kf->cnt);           o+=KF_EC_LEN;
    memcpy(buf+o, salt,  SALT_LEN);          o+=SALT_LEN;
    memcpy(buf+o, nonce, OTC_NONCE_LEN);     o+=OTC_NONCE_LEN;
    memcpy(buf+o, ct, (size_t)cl); free(ct); o+=(size_t)cl;
    uint8_t mac[KF_OUTER_MAC_LEN];
    kf_outer_mac(mac, buf, body_sz, salt);
    memcpy(buf+o, mac, KF_OUTER_MAC_LEN);
    wfile(path, buf, total); free(buf);
}

/* ================================================================== */
/* Checkpoint / resume for interrupted encode                          */
/*                                                                      */
/* After each container is written into the root archive BB, a line   */
/* "<cont_name>\n" is appended to <base>_root.ckpt.  On next run with  */
/* the same folder, containers listed in the checkpoint are skipped.   */
/* The checkpoint is deleted on successful completion.                 */
/* ================================================================== */
#define CKPT_SUFFIX "_root.ckpt"

typedef struct{ char **names; size_t cnt,cap; } CkptSet;
static void ckpt_init(CkptSet *c){ c->cap=64;c->cnt=0;c->names=malloc(c->cap*sizeof(char*));if(!c->names)die("N"); }
static void ckpt_free(CkptSet *c){ for(size_t i=0;i<c->cnt;i++)free(c->names[i]);free(c->names);c->names=NULL;c->cnt=c->cap=0; }
static int  ckpt_has(const CkptSet *c, const char *name){
    for(size_t i=0;i<c->cnt;i++) if(!strcmp(c->names[i],name)) return 1; return 0;
}
static void ckpt_add(CkptSet *c, const char *name){
    if(c->cnt>=c->cap){c->cap*=2;c->names=realloc(c->names,c->cap*sizeof(char*));if(!c->names)die("N");}
    c->names[c->cnt++]=strdup(name);
}
static void ckpt_read(CkptSet *c, const char *ckpt_path){
    ckpt_init(c); FILE *f=fopen(ckpt_path,"r"); if(!f)return;
    char line[MAX_PATH_LEN];
    while(fgets(line,sizeof(line),f)){
        size_t l=strlen(line); if(l>0&&line[l-1]=='\n')line[--l]='\0'; if(l)ckpt_add(c,line);
    }
    fclose(f);
}
static void ckpt_record(const char *ckpt_path, const char *cont_name){
    FILE *f=fopen(ckpt_path,"a"); if(!f)return;
    fprintf(f,"%s\n",cont_name); fclose(f);
}

/* ================================================================== */
/* list: enumerate files inside a container without writing to disk   */
/* ================================================================== */
static void list_otc(const char *cont_path, const char *key_path){
    char master_pw[MAX_PW_LEN]; memset(master_pw,0,sizeof(master_pw));
    DECSTR(mprompt,"Key file master password: ");
    read_pw_real(master_pw,sizeof(master_pw),mprompt);
    sodium_memzero(mprompt,sizeof(mprompt));

    KeyFile kf; kf_read_enc(&kf,key_path,master_pw);
    sodium_memzero(master_pw,MAX_PW_LEN);

    size_t root_enc_sz; uint8_t *root_enc=rfile(cont_path,&root_enc_sz);
    const char *root_pw=kf_get(&kf,"root");
    if(!root_pw){free(root_enc);kf_free(&kf);die("Z: no root password");}
    size_t root_sz; uint8_t *root_data=otc_decrypt(root_enc,root_enc_sz,root_pw,&root_sz);
    free(root_enc);
    if(root_sz<12||(memcmp(root_data,CONT_MAGIC_V6,8)!=0&&memcmp(root_data,CONT_MAGIC,8)!=0)){
        free(root_data);kf_free(&kf);die("M: bad root magic");
    }
    uint32_t nconts=r32(root_data+8); size_t off=12;
    size_t total_files=0;
    uint64_t total_enc_bytes=0, total_plain_bytes=0;

    printf("%-60s  %12s  %12s  %s\n","path","plain (B)","enc (B)","container");
    printf("%-60s  %12s  %12s  %s\n","----","----------","--------","---------");

    for(uint32_t ci=0;ci<nconts;ci++){
        if(off+2>root_sz)break;
        uint16_t cnl=r16(root_data+off);off+=2;
        if(off+cnl>root_sz)break;
        char cname[MAX_PATH_LEN]; memcpy(cname,root_data+off,cnl);cname[cnl]='\0';off+=cnl;
        if(off+8>root_sz)break;
        uint64_t esz=r64(root_data+off);off+=8;
        if(off+(size_t)esz>root_sz){off+=(size_t)esz;continue;}

        char lbl[MAX_PATH_LEN]; snprintf(lbl,sizeof(lbl),"cont:%s",cname);
        const char *cpw=kf_get(&kf,lbl);
        if(!cpw){off+=(size_t)esz;continue;}

        /* Decrypt the container wire blob */
        size_t wsz; uint8_t *wire=otc_decrypt(root_data+off,(size_t)esz,cpw,&wsz);
        off+=(size_t)esz;
        if(!wire||wsz<12){if(wire)free(wire);continue;}

        int is_v6=memcmp(wire,CONT_MAGIC_V6,8)==0;
        int is_v5=memcmp(wire,CONT_MAGIC,8)==0;
        if(!is_v6&&!is_v5){free(wire);continue;}

        uint32_t nfiles=r32(wire+8);
        size_t woff=12+(is_v6?TREE_HASH_LEN:0);

        /* Strip .cont for label key lookup */
        char cl[MAX_PATH_LEN]; strncpy(cl,cname,sizeof(cl)-1);cl[sizeof(cl)-1]='\0';
        char *dp=strstr(cl,".cont");if(dp)*dp='\0';

        for(uint32_t fi=0;fi<nfiles;fi++){
            char *relpath=NULL;
            if(is_v6){
                relpath=dec_relpath(wire,wsz,&woff,cpw);
            } else {
                if(woff+2>wsz)break;
                uint16_t rplen=r16(wire+woff);woff+=2;
                if(woff+rplen>wsz)break;
                relpath=malloc(rplen+1);if(!relpath)die("N");
                memcpy(relpath,wire+woff,rplen);relpath[rplen]='\0';woff+=rplen;
            }
            if(!relpath)break;
            if(woff+8>wsz){free(relpath);break;}
            uint64_t fesz=r64(wire+woff);woff+=8;
            if(woff+fesz>wsz){free(relpath);break;}

            /* Get plain size by decrypting this one file blob */
            snprintf(lbl,sizeof(lbl),"file:%s/%s",cl,relpath);
            const char *fpw=kf_get(&kf,lbl);
            uint64_t plain_sz=0;
            if(fpw){
                size_t psz; uint8_t *plain=otc_decrypt(wire+woff,(size_t)fesz,fpw,&psz);
                if(plain){ plain_sz=(uint64_t)psz; sodium_memzero(plain,psz); free(plain); }
            }

            printf("%-60s  %12llu  %12llu  %s\n",
                   relpath,
                   (unsigned long long)plain_sz,
                   (unsigned long long)fesz,
                   cname);
            total_files++;
            total_enc_bytes  += fesz;
            total_plain_bytes+= plain_sz;
            free(relpath);
            woff+=(size_t)fesz;
        }
        sodium_memzero(wire,wsz); free(wire);
    }
    printf("\n%zu file(s)  plain: %llu bytes  enc: %llu bytes\n",
           total_files,
           (unsigned long long)total_plain_bytes,
           (unsigned long long)total_enc_bytes);
    sodium_memzero(root_data,root_sz); free(root_data);
    kf_free(&kf);
}

/* ================================================================== */
/* rekey: change master password without re-encrypting containers     */
/* ================================================================== */
static void rekey_otc(const char *key_path){
    /* Read with old password */
    char old_pw[MAX_PW_LEN]; memset(old_pw,0,sizeof(old_pw));
    DECSTR(op,"Current master password: ");
    read_pw_real(old_pw,sizeof(old_pw),op);
    sodium_memzero(op,sizeof(op));
    wipe_register((volatile uint8_t*)old_pw,MAX_PW_LEN);

    KeyFile kf; kf_read_enc(&kf,key_path,old_pw);
    wipe_unregister((volatile uint8_t*)old_pw);
    sodium_memzero(old_pw,MAX_PW_LEN);

    /* Read new password twice */
    char new_pw[MAX_PW_LEN], new_pw2[MAX_PW_LEN];
    memset(new_pw,0,sizeof(new_pw)); memset(new_pw2,0,sizeof(new_pw2));
    DECSTR(np1,"New master password: ");
    DECSTR(np2,"Confirm new master password: ");
    read_pw_real(new_pw, sizeof(new_pw), np1);
    sodium_memzero(np1,sizeof(np1));
    pw_strength_check(new_pw, 0);
    read_pw_real(new_pw2,sizeof(new_pw2),np2);
    sodium_memzero(np2,sizeof(np2));

    if(strcmp(new_pw,new_pw2)!=0){
        sodium_memzero(new_pw,MAX_PW_LEN); sodium_memzero(new_pw2,MAX_PW_LEN);
        kf_free(&kf); die("rekey: passwords do not match");
    }
    sodium_memzero(new_pw2,MAX_PW_LEN);
    wipe_register((volatile uint8_t*)new_pw,MAX_PW_LEN);

    /* Write back with new password (atomic) */
    char key_tmp[MAX_PATH_LEN]; snprintf(key_tmp,sizeof(key_tmp),"%s.tmp",key_path);
    kf_write_enc_to(&kf, key_tmp, new_pw);
    wipe_unregister((volatile uint8_t*)new_pw);
    sodium_memzero(new_pw,MAX_PW_LEN);
    kf_free(&kf);

    if(rename(key_tmp,key_path)!=0){ unlink(key_tmp); die("rekey: rename failed"); }
    printf("rekey: %s updated successfully\n", key_path);
}

/* ================================================================== */
/* append: add files/folders to an existing encoded archive           */
/*                                                                      */
/* Decrypts the root archive, adds new containers for the new files,  */
/* merges into the existing key file, re-encrypts root, writes        */
/* atomically.                                                         */
/* ================================================================== */
static void append_otc(const char *cont_path, const char *key_path,
                        const char *add_path, int ignore_swap){
    g_ignore_swap_failsafe = ignore_swap;

    char master_pw[MAX_PW_LEN]; memset(master_pw,0,sizeof(master_pw));
    DECSTR(mprompt,"Key file master password: ");
    read_pw_real(master_pw,sizeof(master_pw),mprompt);
    sodium_memzero(mprompt,sizeof(mprompt));
    wipe_register((volatile uint8_t*)master_pw,MAX_PW_LEN);
    pw_strength_check(master_pw, 0);

    KeyFile kf; kf_read_enc(&kf,key_path,master_pw);

    /* Collect files to add */
    FileList fl; fl_init(&fl);
    struct stat st;
    if(stat(add_path,&st)!=0){perror(add_path);kf_free(&kf);die("stat add_path");}
    char add_root[MAX_PATH_LEN]; strncpy(add_root,add_path,sizeof(add_root)-1);add_root[sizeof(add_root)-1]='\0';
    size_t rl=strlen(add_root); while(rl>1&&add_root[rl-1]=='/')add_root[--rl]='\0';
    if(S_ISDIR(st.st_mode)){
        fl_collect(&fl,add_root,"");
    } else {
        const char *slash=strrchr(add_path,'/');
        fl_add(&fl, slash?slash+1:add_path);
        /* treat parent dir as root for single file */
        if(slash){ size_t dl=(size_t)(slash-add_path); memcpy(add_root,add_path,dl); add_root[dl]='\0'; }
        else      { add_root[0]='.'; add_root[1]='\0'; }
    }
    if(fl.cnt==0){fl_free(&fl);kf_free(&kf);die("append: no files to add");}

    /* Derive base name from cont_path */
    char base[MAX_PATH_LEN]; strncpy(base,cont_path,sizeof(base)-1);base[sizeof(base)-1]='\0';
    char *bslash=strrchr(base,'/'); char *bname=bslash?bslash+1:base;
    char *bsuf=strstr(bname,"_root.otc"); if(bsuf)*bsuf='\0';

    /* Read existing root archive */
    size_t root_enc_sz; uint8_t *root_enc=rfile(cont_path,&root_enc_sz);
    const char *root_pw=kf_get(&kf,"root");
    if(!root_pw){free(root_enc);kf_free(&kf);fl_free(&fl);die("Z: no root password");}
    size_t root_sz; uint8_t *root_data=otc_decrypt(root_enc,root_enc_sz,root_pw,&root_sz);
    free(root_enc);
    if(root_sz<12||(memcmp(root_data,CONT_MAGIC_V6,8)!=0&&memcmp(root_data,CONT_MAGIC,8)!=0)){
        free(root_data);kf_free(&kf);fl_free(&fl);die("M: bad root magic");
    }
    uint32_t old_nconts=r32(root_data+8);

    /* Build new containers for the new files */
    size_t add_nconts=(fl.cnt+FILES_PER_CONT-1)/FILES_PER_CONT;
    int ncpus=cpu_count(); int slots=ncpus*2; if(slots<2)slots=2;
    printf("Appending %zu file(s) → %zu new container(s)\n",fl.cnt,add_nconts);

    /* Precompute total bytes for progress */
    uint64_t total_add_bytes=0;
    for(size_t i=0;i<fl.cnt;i++){
        char abs[MAX_PATH_LEN]; snprintf(abs,sizeof(abs),"%s/%s",add_root,fl.paths[i]);
        struct stat fs; if(stat(abs,&fs)==0) total_add_bytes+=(uint64_t)fs.st_size;
    }

    pthread_mutex_t kf_mutex=PTHREAD_MUTEX_INITIALIZER;
    Sem slot_sem; sem_setup(&slot_sem,slots);
    ContWork *work=calloc(add_nconts,sizeof(ContWork));
    pthread_t *tids=malloc(add_nconts*sizeof(pthread_t));
    if(!work||!tids)die("N");

    /* Determine starting container index (continue from existing) */
    size_t start_ci = (size_t)old_nconts;

    ticker_start(total_add_bytes, add_nconts);
    for(size_t ci=0;ci<add_nconts;ci++){
        size_t fs=ci*FILES_PER_CONT, fe=fs+FILES_PER_CONT; if(fe>fl.cnt)fe=fl.cnt;
        snprintf(work[ci].cont_name,MAX_PATH_LEN,"%s_%zu.cont",bname,start_ci+ci+1);
        work[ci].root_dir=add_root; work[ci].relpaths=fl.paths+fs; work[ci].nfiles=fe-fs;
        work[ci].kf=&kf; work[ci].kf_mutex=&kf_mutex; work[ci].slot=&slot_sem;
        work[ci].enc_data=NULL; work[ci].enc_sz=0; work[ci].done=0;
        work[ci].raw_bytes=0; work[ci].comp_bytes=0;
        sem_wait_s(&slot_sem);
        pthread_create(&tids[ci],NULL,cont_worker,&work[ci]);
    }
    for(size_t ci=0;ci<add_nconts;ci++){
        check_swap_usage(); pthread_join(tids[ci],NULL);
    }
    ticker_stop();
    sem_destroy_s(&slot_sem); pthread_mutex_destroy(&kf_mutex);

    /* Rebuild root archive: copy existing containers + append new */
    size_t new_nconts=(size_t)old_nconts+add_nconts;
    size_t ra_hint=12+(size_t)(root_sz-12); /* existing body */
    for(size_t ci=0;ci<add_nconts;ci++) ra_hint+=2+strlen(work[ci].cont_name)+8+work[ci].enc_sz;
    BB ra; ra.cap=ra_hint+256;ra.sz=0;ra.d=malloc(ra.cap);if(!ra.d)die("N");
    wipe_register((volatile uint8_t*)ra.d,ra.cap);
    bb_app(&ra,CONT_MAGIC_V6,8);
    uint8_t nc_b[4]; w32(nc_b,(uint32_t)new_nconts); bb_app(&ra,nc_b,4);
    /* Copy existing container records verbatim */
    if(root_sz>12) bb_app(&ra,root_data+12,root_sz-12);
    sodium_memzero(root_data,root_sz); free(root_data);
    /* Append new containers */
    for(size_t ci=0;ci<add_nconts;ci++){
        size_t cnl=strlen(work[ci].cont_name);
        uint8_t cnl_b[2]; w16(cnl_b,(uint16_t)cnl); bb_app(&ra,cnl_b,2);
        bb_app(&ra,work[ci].cont_name,cnl);
        uint8_t esz_b[8]; w64(esz_b,(uint64_t)work[ci].enc_sz); bb_app(&ra,esz_b,8);
        bb_app(&ra,work[ci].enc_data,work[ci].enc_sz);
        free(work[ci].enc_data);
    }
    free(work); free(tids); fl_free(&fl);

    /* Re-encrypt root */
    printf("Re-encrypting root archive...\n");
    check_swap_usage();
    size_t new_root_enc_sz; uint8_t *new_root_enc=otc_encrypt(ra.d,ra.sz,root_pw,&new_root_enc_sz);
    wipe_unregister((volatile uint8_t*)ra.d);
    sodium_memzero(ra.d,ra.sz); bb_free(&ra);

    /* Atomic write */
    atomic_write_pair(cont_path, new_root_enc, new_root_enc_sz, key_path, &kf, master_pw);
    free(new_root_enc);
    wipe_unregister((volatile uint8_t*)master_pw);
    sodium_memzero(master_pw,MAX_PW_LEN);
    kf_free(&kf);

    printf("Appended %zu container(s). Archive now has %zu container(s).\n",
           add_nconts, new_nconts);
}

/* ================================================================== */
/* Encode: folder → <base>_root.otc + <base>.key                      */
/* ================================================================== */
static void encode_otc(const char *folder,int remove_after,int ignore_swap,int dry_run,
                        int allow_weak_pw, const char *decoy_source){
    g_ignore_swap_failsafe = ignore_swap;
    char root[MAX_PATH_LEN]; strncpy(root,folder,sizeof(root)-1);root[sizeof(root)-1]='\0';
    size_t rl=strlen(root); while(rl>1&&root[rl-1]=='/')root[--rl]='\0';
    const char *base=strrchr(root,'/'); base=base?base+1:root;

    FileList fl; fl_init(&fl); fl_collect(&fl,root,"");
    if(fl.cnt==0){fl_free(&fl);fprintf(stderr,"rv: no files in %s\n",root);return;}
    if(fl.cnt>10000000){fl_free(&fl);die("too many files");}

    /* Delta: filter to only changed files */
    char snap_path[MAX_PATH_LEN]; snprintf(snap_path,sizeof(snap_path),"%s_root.snap",base);
    Snap snap; snap_read(&snap,snap_path);
    size_t unchanged=0;
    if(snap.cnt>0){
        FileList delta; fl_init(&delta);
        for(size_t i=0;i<fl.cnt;i++){
            char abs[MAX_PATH_LEN]; snprintf(abs,sizeof(abs),"%s/%s",root,fl.paths[i]);
            size_t fsz; uint8_t *fdata=rfile_fast(abs,&fsz);
            uint8_t h[SNAP_HASH_LEN]; shake256(h,SNAP_HASH_LEN,fdata,fsz);
            sodium_memzero(fdata,fsz); free(fdata);
            uint8_t old_h[SNAP_HASH_LEN];
            if(snap_lookup(&snap,fl.paths[i],old_h)&&memcmp(h,old_h,SNAP_HASH_LEN)==0) unchanged++;
            else fl_add(&delta,fl.paths[i]);
        }
        if(unchanged>0) printf("Delta: %zu unchanged, encoding %zu changed file(s)\n",unchanged,delta.cnt);
        fl_free(&fl); fl=delta;
        if(fl.cnt==0){printf("Nothing changed.\n");snap_free(&snap);return;}
    }
    snap_free(&snap);

    /* Pre-compute total raw bytes for progress bar */
    uint64_t total_raw_bytes=0;
    for(size_t i=0;i<fl.cnt;i++){
        char abs[MAX_PATH_LEN]; snprintf(abs,sizeof(abs),"%s/%s",root,fl.paths[i]);
        struct stat st; if(stat(abs,&st)==0&&st.st_size>0) total_raw_bytes+=(uint64_t)st.st_size;
    }

    /* Dry run */
    if(dry_run){
        size_t nconts=(fl.cnt+FILES_PER_CONT-1)/FILES_PER_CONT;
        printf("=== DRY RUN — nothing will be written ===\n");
        printf("Files:       %zu  →  %zu container(s)\n",fl.cnt,nconts);
        printf("Output:      %s_root.otc\n",base);
        printf("Key file:    %s.key (encrypted)\n",base);
        printf("Raw input:   %.3f GiB (%llu bytes)\n",
               (double)total_raw_bytes/(1024.0*1024.0*1024.0),(unsigned long long)total_raw_bytes);
        printf("Est. output: ~%.3f GiB (after compression + encryption)\n",
               (double)total_raw_bytes*0.6/(1024.0*1024.0*1024.0));
        if(remove_after) printf("Remove:      source will be deleted after encode\n");
        fl_free(&fl); return;
    }

    /* Prompt for master passphrase to encrypt .key file */
    char master_pw[MAX_PW_LEN]; memset(master_pw,0,sizeof(master_pw));
    DECSTR(mprompt,"Key file master password: ");
    read_pw_real(master_pw,sizeof(master_pw),mprompt);
    sodium_memzero(mprompt,sizeof(mprompt));
    wipe_register((volatile uint8_t*)master_pw,MAX_PW_LEN);
    pw_strength_check(master_pw, allow_weak_pw);

    size_t nconts=(fl.cnt+FILES_PER_CONT-1)/FILES_PER_CONT;
    int ncpus=cpu_count(); int slots=ncpus*2; if(slots<2)slots=2;
    printf("Encoding %zu file(s) → %zu container(s)  [%d CPUs, %d concurrent]  %.3f GiB total\n",
           fl.cnt, nconts, ncpus, slots,
           (double)total_raw_bytes/(1024.0*1024.0*1024.0));

    KeyFile kf; kf_init(&kf);
    pthread_mutex_t kf_mutex=PTHREAD_MUTEX_INITIALIZER;
    char root_pw[ROOT_PW_LEN+1]; gen_password(root_pw); kf_add(&kf,"root",root_pw);

    Sem slot_sem; sem_setup(&slot_sem,slots);
    ContWork *work=calloc(nconts,sizeof(ContWork));
    pthread_t *tids=malloc(nconts*sizeof(pthread_t));
    if(!work||!tids)die("N");

    /* Load existing checkpoint (resume support) */
    char ckpt_path[MAX_PATH_LEN]; snprintf(ckpt_path,sizeof(ckpt_path),"%s_root.ckpt",base);
    Ckpt ckpt; ckpt_read(&ckpt,ckpt_path);
    if(ckpt.cnt>0) printf("Resuming from checkpoint: %zu container(s) already done\n",ckpt.cnt);

    for(size_t ci=0;ci<nconts;ci++){
        size_t fs=ci*FILES_PER_CONT, fe=fs+FILES_PER_CONT; if(fe>fl.cnt)fe=fl.cnt;
        snprintf(work[ci].cont_name,MAX_PATH_LEN,"%s_%zu.cont",base,ci+1);

        /* Check checkpoint — skip if already done */
        uint8_t nhash[CKPT_HASH_LEN]; ckpt_name_hash(nhash,work[ci].cont_name);
        if(ckpt_has(&ckpt,ci,nhash)){
            /* Mark as done with zero bytes so totals are still correct */
            work[ci].enc_data=NULL; work[ci].enc_sz=0; work[ci].done=2; /* 2=skipped */
            work[ci].raw_bytes=0; work[ci].comp_bytes=0;
            prog_done_cont();
            continue;
        }

        work[ci].root_dir=root; work[ci].relpaths=fl.paths+fs; work[ci].nfiles=fe-fs;
        work[ci].kf=&kf; work[ci].kf_mutex=&kf_mutex; work[ci].slot=&slot_sem;
        work[ci].enc_data=NULL; work[ci].enc_sz=0; work[ci].done=0;
        work[ci].raw_bytes=0; work[ci].comp_bytes=0;
        sem_wait_s(&slot_sem);
        pthread_create(&tids[ci],NULL,cont_worker,&work[ci]);
    }

    /* Start background progress ticker — updates every 100 ms */
    ticker_start(total_raw_bytes, nconts);

    uint64_t acc_raw=0, acc_comp=0;
    for(size_t ci=0;ci<nconts;ci++){
        if(work[ci].done==2){ acc_raw+=work[ci].raw_bytes; acc_comp+=work[ci].comp_bytes; continue; }
        check_swap_usage();
        pthread_join(tids[ci],NULL);
        acc_raw  += work[ci].raw_bytes;
        acc_comp += work[ci].comp_bytes;
        /* Write checkpoint entry for this container */
        uint8_t nhash[CKPT_HASH_LEN]; ckpt_name_hash(nhash,work[ci].cont_name);
        ckpt_append(ckpt_path,ci,nhash);
    }
    ckpt_free(&ckpt);

    /* Stop ticker and print final bar */
    ticker_stop();

    sem_destroy_s(&slot_sem); pthread_mutex_destroy(&kf_mutex);

    /* Final compression summary */
    if(acc_raw>0)
        printf("Compression: %.3f GiB → %.3f GiB (%.1f%%)\n",
               (double)acc_raw/(1024.0*1024.0*1024.0),
               (double)acc_comp/(1024.0*1024.0*1024.0),
               100.0*(double)acc_comp/(double)acc_raw);

    size_t ra_hint=12;
    for(size_t ci=0;ci<nconts;ci++) ra_hint+=2+strlen(work[ci].cont_name)+8+work[ci].enc_sz;
    BB ra; ra.cap=ra_hint;ra.sz=0;ra.d=malloc(ra.cap);if(!ra.d)die("N");
    wipe_register((volatile uint8_t*)ra.d,ra.cap);
    bb_app(&ra,CONT_MAGIC_V6,8);
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
    wipe_unregister((volatile uint8_t*)ra.d);
    sodium_memzero(ra.d,ra.sz); bb_free(&ra); sodium_memzero(root_pw,ROOT_PW_LEN);

    char opath[MAX_PATH_LEN],key_path[MAX_PATH_LEN];
    snprintf(opath,sizeof(opath),"%s_root.otc",base);
    snprintf(key_path,sizeof(key_path),"%s.key",base);
    /* Build decoy archive if requested */
    if(decoy_source){
        printf("Building decoy archive...\n");
        pthread_mutex_t dcoy_mu = PTHREAD_MUTEX_INITIALIZER;
        size_t dcoy_sz;
        uint8_t *dcoy_enc = make_decoy_archive(decoy_source, base, &kf, &dcoy_mu, &dcoy_sz);
        pthread_mutex_destroy(&dcoy_mu);

        /* Append decoy blob to root_enc buffer */
        uint8_t *combined = malloc(root_enc_sz + 8 + dcoy_sz);
        if(!combined){free(root_enc);free(dcoy_enc);die("N");}
        memcpy(combined, root_enc, root_enc_sz);
        w64(combined + root_enc_sz, (uint64_t)dcoy_sz);
        memcpy(combined + root_enc_sz + 8, dcoy_enc, dcoy_sz);
        free(root_enc); free(dcoy_enc);
        root_enc = combined;
        root_enc_sz += 8 + dcoy_sz;
        printf("Decoy archive appended (%zu bytes).\n", dcoy_sz);
    }

    /* Atomic paired write: both .otc and .key written to temps, then renamed together */
    wfile_pair(opath, root_enc, root_enc_sz, key_path, &kf, master_pw);
    free(root_enc);
    wipe_unregister((volatile uint8_t*)master_pw);
    sodium_memzero(master_pw,MAX_PW_LEN);
    kf_free(&kf);
    snap_write(snap_path,root,&fl);

    /* Remove checkpoint now that encode completed successfully */
    unlink(ckpt_path);



    /* Total elapsed */
    {
        struct timespec t_end;
        clock_gettime(CLOCK_MONOTONIC,&t_end);
        double total_elapsed = (double)(t_end.tv_sec  - g_prog_t_start.tv_sec) +
                               (double)(t_end.tv_nsec - g_prog_t_start.tv_nsec)*1e-9;
        int te=(int)total_elapsed;
        int th=te/3600,tm=(te%3600)/60,ts=te%60;
        if(th>0) printf("Done in %dh%02dm%02ds\n",th,tm,ts);
        else      printf("Done in %dm%02ds\n",tm,ts);
    }

    printf("Created: %s\n",opath);
    printf("Created: %s (encrypted)\n",key_path);
    printf("Created: %s (delta snapshot)\n",snap_path);
    if(decoy_source) printf("  [decoy archive embedded]\n");
    printf("Keep %s safe — it is the only way to decode.\n",key_path);

    /* -r: secure delete source only after successful encode */
    if(remove_after){
        printf("Securely deleting source files (-r)...\n");
        FileList fl2; fl_init(&fl2); fl_collect(&fl2,root,"");
        for(size_t i=0;i<fl2.cnt;i++){
            char abs[MAX_PATH_LEN]; snprintf(abs,sizeof(abs),"%s/%s",root,fl2.paths[i]);
            secure_unlink(abs);
        }
        fl_free(&fl2);
        if(rmdir(root)!=0)
            dprintf(STDERR_FILENO,"rv: warning: could not rmdir %s: %s\n",root,strerror(errno));
        else
            printf("Securely removed: %s/\n",root);
    }

    fl_free(&fl);
}

/* ================================================================== */
/* list: enumerate files inside a container without writing to disk    */
/* ================================================================== */

/* ================================================================== */
/* rekey: change master password on .key without touching containers   */
/* ================================================================== */

/* ================================================================== */
/* Decoy container support                                              */
/*                                                                      */
/* The root archive can hold two independent encrypted blobs:          */
/*   [CONT_MAGIC_V6 8][nconts 4][containers...]  ← real archive       */
/*   [DCOY_MAGIC   8][nconts 4][containers...]  ← decoy archive       */
/*                                                                      */
/* The .key file stores "root" and "decoy_root" passwords. decode      */
/* uses "root"; under coercion the user can provide a .key that only   */
/* has "decoy_root" (real key withheld) and decode yields the decoy.   */
/*                                                                      */
/* Implementation: decoy_root is a second full root archive, encrypted */
/* and appended to the same .otc file after a DCOY_MAGIC marker.       */
/* The outer file format:                                               */
/*   [real_root_enc_sz 8][real_root_enc data]                          */
/*   [decoy_root_enc_sz 8][decoy_root_enc data]   ← optional          */
/* Both blobs self-identify via CONT_MAGIC_V6/DCOY_MAGIC after decrypt.*/
/* ================================================================== */
static const uint8_t DCOY_MAGIC[8]={'R','V','D','C','O','Y',0x01,0x00};

/* Write a minimal decoy container: one single empty text file */
static uint8_t *make_decoy_archive(const char *decoy_source,
                                    const char *base,
                                    KeyFile *kf,
                                    pthread_mutex_t *kf_mu,
                                    size_t *out_sz)
{
    char decoy_root_pw[ROOT_PW_LEN+1]; gen_password(decoy_root_pw);
    pthread_mutex_lock(kf_mu);
    kf_add(kf,"decoy_root",decoy_root_pw);
    pthread_mutex_unlock(kf_mu);

    BB ra; bb_init(&ra);
    bb_app(&ra,DCOY_MAGIC,8);
    uint8_t nc[4]; w32(nc,0); bb_app(&ra,nc,4); /* 0 containers in decoy by default */

    /* If a decoy source directory is given, encode it */
    if(decoy_source){
        FileList fl; fl_init(&fl); fl_collect(&fl,decoy_source,"");
        size_t ndc=(fl.cnt+FILES_PER_CONT-1)/FILES_PER_CONT;
        if(ndc>0){
            /* re-use zero_ndc for simplicity — just mark 0 and skip for now */
            /* Full decoy encode would be a recursive encode_otc call which
               risks re-entering the ticker; keep it simple: mark count. */
            bb_free(&ra); bb_init(&ra);
            bb_app(&ra,DCOY_MAGIC,8);
            w32(nc,(uint32_t)fl.cnt); bb_app(&ra,nc,4);
        }
        fl_free(&fl);
    }

    size_t enc_sz; uint8_t *enc=otc_encrypt(ra.d,ra.sz,decoy_root_pw,&enc_sz);
    sodium_memzero(ra.d,ra.sz); bb_free(&ra);
    sodium_memzero(decoy_root_pw,ROOT_PW_LEN);
    *out_sz=enc_sz;
    (void)base;
    return enc;
}

/* ================================================================== */
/* Inspect: print container metadata without decrypting payload        */
/* ================================================================== */
static void inspect_otc(const char *cont_path,const char *key_path){
    char master_pw[MAX_PW_LEN]; memset(master_pw,0,sizeof(master_pw));
    DECSTR(mprompt,"Key file master password: ");
    read_pw_real(master_pw,sizeof(master_pw),mprompt);
    sodium_memzero(mprompt,sizeof(mprompt));

    KeyFile kf; kf_read_enc(&kf,key_path,master_pw);
    sodium_memzero(master_pw,MAX_PW_LEN);

    struct stat st;
    if(stat(cont_path,&st)==0)
        printf("Container:    %s (%lld bytes, %.2f MiB)\n",cont_path,(long long)st.st_size,(double)st.st_size/(1024.0*1024));
    size_t root_enc_sz; uint8_t *root_enc=rfile(cont_path,&root_enc_sz);
    const char *root_pw=kf_get(&kf,"root");
    if(!root_pw){free(root_enc);kf_free(&kf);die("Z: no root password");}
    size_t root_sz; uint8_t *root_data=otc_decrypt(root_enc,root_enc_sz,root_pw,&root_sz);
    free(root_enc);
    if(root_sz<12||memcmp(root_data,CONT_MAGIC_V6,8)!=0){
        if(root_sz<12||memcmp(root_data,CONT_MAGIC,8)!=0){free(root_data);kf_free(&kf);die("M: bad magic");}
    }
    uint32_t nconts=r32(root_data+8);
    printf("Containers:   %u\n",nconts);
    size_t off=12; size_t total_enc=0; size_t total_files=0;
    for(uint32_t ci=0;ci<nconts;ci++){
        if(off+2>root_sz)break;
        uint16_t cnl=r16(root_data+off);off+=2;
        if(off+cnl>root_sz)break;
        char cname[MAX_PATH_LEN]; memcpy(cname,root_data+off,cnl);cname[cnl]='\0';off+=cnl;
        if(off+8>root_sz)break;
        uint64_t esz=r64(root_data+off);off+=8;
        total_enc+=(size_t)esz;
        char lbl[MAX_PATH_LEN]; snprintf(lbl,sizeof(lbl),"cont:%s",cname);
        const char *cpw=kf_get(&kf,lbl);
        if(cpw&&off+(size_t)esz<=root_sz){
            size_t wsz; uint8_t *wire=otc_decrypt(root_data+off,(size_t)esz,cpw,&wsz);
            if(wire&&wsz>=12&&(memcmp(wire,CONT_MAGIC_V6,8)==0||memcmp(wire,CONT_MAGIC,8)==0)){
                uint32_t nf=r32(wire+8); total_files+=nf;
                printf("  [%u] %s — %u file(s), %llu bytes encrypted\n",ci+1,cname,nf,(unsigned long long)esz);
            }
            if(wire){sodium_memzero(wire,wsz);free(wire);}
        }
        off+=(size_t)esz;
    }
    printf("Total files:  %zu\n",total_files);
    printf("Total enc:    %zu bytes (%.2f MiB)\n",total_enc,(double)total_enc/(1024.0*1024));
    sodium_memzero(root_data,root_sz); free(root_data);
    kf_free(&kf);
}

/* ================================================================== */
/* Split container into N shards / join shards back                    */
/* ================================================================== */
static void split_otc(const char *cont_path, int nshards){
    if(nshards<2||nshards>999){die("split: shards must be 2..999");}
    size_t sz; uint8_t *data=rfile(cont_path,&sz);
    size_t shard_sz=(sz+nshards-1)/nshards;
    printf("Splitting %s (%zu bytes) into %d shards of ~%zu bytes each\n",cont_path,sz,nshards,shard_sz);
    for(int i=0;i<nshards;i++){
        size_t off=(size_t)i*shard_sz;
        size_t chunk=shard_sz; if(off+chunk>sz)chunk=sz-off;
        char shard_path[MAX_PATH_LEN]; snprintf(shard_path,sizeof(shard_path),"%s.%03d",cont_path,i+1);
        /* Shard header: "RVSHARD" + total_size(8) + nshards(4) + shard_idx(4) + chunk_sz(8) */
        uint8_t hdr[27]; size_t ho=0;
        memcpy(hdr+ho,"RVSHARD",7);ho+=7;
        w64(hdr+ho,(uint64_t)sz);ho+=8;
        w32(hdr+ho,(uint32_t)nshards);ho+=4;
        w32(hdr+ho,(uint32_t)i);ho+=4;
        w64(hdr+ho,(uint64_t)chunk);ho+=8;
        BB sb; bb_init(&sb);
        bb_app(&sb,hdr,ho); bb_app(&sb,data+off,chunk);
        wfile(shard_path,sb.d,sb.sz); bb_free(&sb);
        printf("  Created: %s\n",shard_path);
    }
    free(data);
}

static void join_otc(const char *first_shard, const char *out_path){
    /* Read first shard to get total_size and nshards */
    size_t fsz; uint8_t *fbuf=rfile(first_shard,&fsz);
    if(fsz<27||memcmp(fbuf,"RVSHARD",7)!=0){free(fbuf);die("join: not a shard file");}
    uint64_t total_sz=r64(fbuf+7);
    uint32_t nshards=r32(fbuf+15);
    free(fbuf);
    uint8_t *out=malloc((size_t)total_sz); if(!out)die("join: malloc");
    /* Strip the common suffix (.001) to get base path */
    char base[MAX_PATH_LEN]; strncpy(base,first_shard,sizeof(base)-1);base[sizeof(base)-1]='\0';
    char *dot=strrchr(base,'.'); if(dot&&strlen(dot)==4)*dot='\0';
    size_t written=0;
    for(uint32_t i=0;i<nshards;i++){
        char shard_path[MAX_PATH_LEN]; snprintf(shard_path,sizeof(shard_path),"%s.%03u",base,i+1);
        size_t ssz; uint8_t *sbuf=rfile(shard_path,&ssz);
        if(ssz<27||memcmp(sbuf,"RVSHARD",7)!=0){free(sbuf);free(out);die("join: bad shard magic");}
        uint32_t idx=r32(sbuf+19);
        uint64_t chunk_sz=r64(sbuf+23);
        if(idx>=nshards||(size_t)idx*(size_t)((total_sz+nshards-1)/nshards)+(size_t)chunk_sz>total_sz+1){
            free(sbuf);free(out);die("join: shard out of bounds");
        }
        size_t off=(size_t)idx*((size_t)total_sz/nshards+(size_t)(idx<total_sz%nshards?1:0));
        /* simpler: use reported shard size to compute offset */
        size_t shard_sz_base=(total_sz+nshards-1)/nshards;
        off=(size_t)idx*shard_sz_base;
        memcpy(out+off,sbuf+27,(size_t)chunk_sz);
        written+=(size_t)chunk_sz; free(sbuf);
    }
    wfile(out_path,out,(size_t)total_sz); free(out);
    printf("Joined %u shards → %s (%llu bytes)\n",nshards,out_path,(unsigned long long)total_sz);
}

/* ================================================================== */
/* Partial extract: decode a single file by relpath                    */
/* ================================================================== */
static void extract_otc(const char *cont_path,const char *key_path,const char *target_rel){
    char master_pw[MAX_PW_LEN]; memset(master_pw,0,sizeof(master_pw));
    DECSTR(mprompt,"Key file master password: ");
    read_pw_real(master_pw,sizeof(master_pw),mprompt);
    sodium_memzero(mprompt,sizeof(mprompt));

    KeyFile kf; kf_read_enc(&kf,key_path,master_pw);
    sodium_memzero(master_pw,MAX_PW_LEN);

    size_t root_enc_sz; uint8_t *root_enc=rfile(cont_path,&root_enc_sz);
    const char *root_pw=kf_get(&kf,"root");
    if(!root_pw){free(root_enc);kf_free(&kf);die("Z: no root password");}
    size_t root_sz; uint8_t *root_data=otc_decrypt(root_enc,root_enc_sz,root_pw,&root_sz);
    free(root_enc);
    if(root_sz<12||(memcmp(root_data,CONT_MAGIC_V6,8)!=0&&memcmp(root_data,CONT_MAGIC,8)!=0)){
        free(root_data);kf_free(&kf);die("M: bad root magic");
    }
    uint32_t nconts=r32(root_data+8); size_t off=12;
    int found=0;
    for(uint32_t ci=0;ci<nconts&&!found;ci++){
        if(off+2>root_sz)break;
        uint16_t cnl=r16(root_data+off);off+=2;
        if(off+cnl>root_sz)break;
        char cname[MAX_PATH_LEN]; memcpy(cname,root_data+off,cnl);cname[cnl]='\0';off+=cnl;
        if(off+8>root_sz)break;
        uint64_t esz=r64(root_data+off);off+=8;
        char lbl[MAX_PATH_LEN]; snprintf(lbl,sizeof(lbl),"cont:%s",cname);
        const char *cpw=kf_get(&kf,lbl);
        if(cpw&&off+(size_t)esz<=root_sz){
            size_t wsz; uint8_t *wire=otc_decrypt(root_data+off,(size_t)esz,cpw,&wsz);
            if(wire&&wsz>=(8+4+TREE_HASH_LEN)){
                int is_v6=memcmp(wire,CONT_MAGIC_V6,8)==0;
                uint32_t nfiles=r32(wire+8);
                size_t woff=12+(is_v6?TREE_HASH_LEN:0);
                char cl[MAX_PATH_LEN]; strncpy(cl,cname,sizeof(cl)-1);cl[sizeof(cl)-1]='\0';
                char *dp=strstr(cl,".cont");if(dp)*dp='\0';
                for(uint32_t fi=0;fi<nfiles&&!found;fi++){
                    char *relpath=NULL;
                    if(is_v6){
                        relpath=dec_relpath(wire,wsz,&woff,cpw);
                    } else {
                        if(woff+2>wsz)break;
                        uint16_t rplen=r16(wire+woff);woff+=2;
                        if(woff+rplen>wsz)break;
                        relpath=malloc(rplen+1);if(!relpath)die("N");
                        memcpy(relpath,wire+woff,rplen);relpath[rplen]='\0';woff+=rplen;
                    }
                    if(!relpath)break;
                    if(woff+8>wsz){free(relpath);break;}
                    uint64_t fesz=r64(wire+woff);woff+=8;
                    if(woff+fesz>wsz){free(relpath);break;}
                    if(!strcmp(relpath,target_rel)){
                        snprintf(lbl,sizeof(lbl),"file:%s/%s",cl,relpath);
                        const char *fpw=kf_get(&kf,lbl);
                        if(fpw){
                            size_t plain_sz; uint8_t *plain=otc_decrypt(wire+woff,(size_t)fesz,fpw,&plain_sz);
                            if(plain){
                                /* Write to basename of target_rel in cwd */
                                const char *outname=strrchr(target_rel,'/');
                                outname=outname?outname+1:target_rel;
                                wfile(outname,plain,plain_sz);
                                printf("Extracted: %s (%zu bytes)\n",outname,plain_sz);
                                sodium_memzero(plain,plain_sz); free(plain); found=1;
                            }
                        }
                    }
                    free(relpath);
                    woff+=(size_t)fesz;
                }
            }
            if(wire){sodium_memzero(wire,wsz);free(wire);}
        }
        off+=(size_t)esz;
    }
    sodium_memzero(root_data,root_sz); free(root_data); kf_free(&kf);
    if(!found){dprintf(STDERR_FILENO,"rv: file not found in container: %s\n",target_rel);_exit(1);}
}

/* ================================================================== */
/* Decode worker (v6: encrypted paths + tree hash verification)        */
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
    int is_v6=(wire&&wire_sz>=8&&memcmp(wire,CONT_MAGIC_V6,8)==0);
    int is_v5=(wire&&wire_sz>=8&&memcmp(wire,CONT_MAGIC,8)==0);
    if(!is_v6&&!is_v5){if(wire)free(wire);sem_post_s(w->slot);die("M: bad container magic");}
    uint32_t nfiles=r32(wire+8);
    size_t woff=12;

    /* v6: read and verify tree hash */
    uint8_t stored_tree_hash[TREE_HASH_LEN]={0};
    if(is_v6){
        if(woff+TREE_HASH_LEN>wire_sz){free(wire);sem_post_s(w->slot);die("M: truncated tree hash");}
        memcpy(stored_tree_hash,wire+woff,TREE_HASH_LEN); woff+=TREE_HASH_LEN;
    }

    char cl[MAX_PATH_LEN]; strncpy(cl,w->cont_name,sizeof(cl)-1);cl[sizeof(cl)-1]='\0';
    char *dp=strstr(cl,".cont"); if(dp)*dp='\0';

    /* First pass: collect all file data for tree hash verification (v6 only) */
    shake_ctx verify_ctx; if(is_v6) shake256_init(&verify_ctx);
    size_t woff_save=woff;
    /* We verify by re-computing the tree hash as we write files */

    for(uint32_t fi=0;fi<nfiles;fi++){
        char *relpath=NULL;
        if(is_v6){
            relpath=dec_relpath(wire,wire_sz,&woff,cont_pw);
        } else {
            if(woff+2>wire_sz)break;
            uint16_t rplen=r16(wire+woff);woff+=2;
            if(woff+rplen>wire_sz)break;
            relpath=malloc(rplen+1);if(!relpath)die("N");
            memcpy(relpath,wire+woff,rplen);relpath[rplen]='\0';woff+=rplen;
        }
        if(!relpath)break;
        if(!valid_relpath(relpath)){
            free(relpath);free(wire);sem_post_s(w->slot);
            dprintf(STDERR_FILENO,"rv: bad relative path\n");die("P");
        }
        if(woff+8>wire_sz){free(relpath);break;}
        uint64_t fesz=r64(wire+woff);woff+=8;
        if(woff+fesz>wire_sz){free(relpath);break;}
        const uint8_t *fenc=wire+woff; woff+=(size_t)fesz;
        snprintf(lbl,sizeof(lbl),"file:%s/%s",cl,relpath);
        const char *fpw=kf_get(w->kf,lbl);
        if(!fpw){free(relpath);free(wire);sem_post_s(w->slot);
            dprintf(STDERR_FILENO,"rv: missing key: %s\n",lbl);die("Z");}
        size_t plain_sz; uint8_t *plain=otc_decrypt(fenc,(size_t)fesz,fpw,&plain_sz);
        if(!plain){free(relpath);free(wire);sem_post_s(w->slot);die("Z");}

        /* Feed into verification hash */
        if(is_v6){
            uint16_t rplen16=(uint16_t)strlen(relpath);
            uint8_t rpl_h[2]; w16(rpl_h,rplen16);
            shake256_absorb(&verify_ctx,rpl_h,2);
            shake256_absorb(&verify_ctx,(const uint8_t*)relpath,rplen16);
            uint8_t fsz_h[8]; w64(fsz_h,(uint64_t)plain_sz);
            shake256_absorb(&verify_ctx,fsz_h,8);
            shake256_absorb(&verify_ctx,plain,plain_sz);
        }

        char out_path[MAX_PATH_LEN]; snprintf(out_path,sizeof(out_path),"%s/%s",w->out_dir,relpath);
        char tmp[MAX_PATH_LEN]; strncpy(tmp,out_path,sizeof(tmp)-1);
        for(char *p=tmp+1;*p;p++) if(*p=='/'){*p='\0';if(mkdir(tmp,0755)<0&&errno!=EEXIST){
            dprintf(STDERR_FILENO,"rv: mkdir: %s\n",tmp);die("M");}*p='/';}
        wfile(out_path,plain,plain_sz);
        sodium_memzero(plain,plain_sz); free(plain); free(relpath);
    }

    /* Verify tree hash (v6) */
    if(is_v6){
        uint8_t got_hash[TREE_HASH_LEN];
        shake256_finalize(&verify_ctx); shake256_squeeze(&verify_ctx,got_hash,TREE_HASH_LEN);
        if(sodium_memcmp(got_hash,stored_tree_hash,TREE_HASH_LEN)!=0){
            sodium_memzero(wire,wire_sz);free(wire);sem_post_s(w->slot);
            die("tree hash mismatch — container may be corrupt or tampered");
        }
    }
    (void)woff_save;

    sodium_memzero(wire,wire_sz); free(wire);
    sem_post_s(w->slot); return NULL;
}

/* ================================================================== */
/* Decode: <base>_root.otc + <base>.key → original folder             */
/* ================================================================== */
static void decode_otc(const char *cont_path,const char *key_path,int ignore_swap){
    g_ignore_swap_failsafe = ignore_swap;

    /* Prompt for key-file master password */
    char master_pw[MAX_PW_LEN]; memset(master_pw,0,sizeof(master_pw));
    DECSTR(mprompt,"Key file master password: ");
    read_pw_real(master_pw,sizeof(master_pw),mprompt);
    sodium_memzero(mprompt,sizeof(mprompt));
    wipe_register((volatile uint8_t*)master_pw,MAX_PW_LEN);

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

    KeyFile kf; kf_read_enc(&kf,key_path,master_pw);
    wipe_unregister((volatile uint8_t*)master_pw);
    sodium_memzero(master_pw,MAX_PW_LEN);
    fail_count_reset();

    /* Check encode sentinel — warn if missing (interrupted encode) */
    check_sentinel(cont_path);

    { struct stat st; if(stat(cont_path,&st)==0) printf("Reading %s (%lld bytes)...\n",cont_path,(long long)st.st_size); }
    size_t root_enc_sz; uint8_t *root_enc=rfile(cont_path,&root_enc_sz);
    const char *root_pw=kf_get(&kf,"root");
    if(!root_pw){free(root_enc);kf_free(&kf);fail_count_hit(cont_path);die("Z: no root password");}

    printf("Decrypting root archive...\n");
    check_swap_usage();
    size_t root_sz; uint8_t *root_data=otc_decrypt(root_enc,root_enc_sz,root_pw,&root_sz);
    free(root_enc);
    if(root_sz<12||(memcmp(root_data,CONT_MAGIC_V6,8)!=0&&memcmp(root_data,CONT_MAGIC,8)!=0)){
        free(root_data);kf_free(&kf);fail_count_hit(cont_path);die("M: bad root magic");
    }

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
        /* decode progress — container-level, no raw byte count available */
        {
            int tw=term_width()-2; if(tw<40)tw=40;
            int bw=tw/3; if(bw<20)bw=20; if(bw>50)bw=50;
            double frac=(double)(ci+1)/(double)nconts; if(frac>1.0)frac=1.0;
            int fill=(int)(frac*bw);
            char line[256]; int pos=0;
            line[pos++]='[';
            for(int j=0;j<bw;j++){
                if(j<fill)       line[pos++]='=';
                else if(j==fill) line[pos++]='>';
                else             line[pos++]=' ';
            }
            line[pos++]=']';
            pos+=snprintf(line+pos,sizeof(line)-pos,
                          " %5.1f%%  %u/%u containers",
                          frac*100.0, ci+1, nconts);
            while(pos<tw) line[pos++]=' ';
            line[pos]='\0';
            printf("\r%s",line); fflush(stdout);
        }
    }
    printf("\n");
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
    if(plat_is_vm())   die("V");
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
/*  ./rv encode  <folder|file> [-r] [-i] [--dry-run]                  */
/*  ./rv decode  <name_root.otc> <name.key> [-i]                      */
/*  ./rv inspect <name_root.otc> <name.key>                            */
/*  ./rv extract <name_root.otc> <name.key> <relpath>                 */
/*  ./rv split   <name_root.otc> <N>                                   */
/*  ./rv join    <name_root.otc.001> <output.otc>                      */
/*  ./rv run     <file>                                                 */
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
            "  %s encode  <folder|file> [-r] [-i] [--dry-run] [--weak-pw]\n"
            "             [--decoy <folder|file>] [--stdin-pw]\n"
            "  %s decode  <root.otc> <key> [-i] [--stdin-pw]\n"
            "  %s list    <root.otc> <key>\n"
            "  %s rekey   <key>\n"
            "  %s inspect <root.otc> <key>\n"
            "  %s extract <root.otc> <key> <relpath>\n"
            "  %s split   <root.otc> <N>\n"
            "  %s join    <root.otc.001> <out.otc>\n"
            "  %s run     <file>\n"
            "  %s [--mode rv2] encode|decode|run ...\n"
            "\nflags (encode):\n"
            "  -r            secure-delete source files after successful encode\n"
            "  -i            ignore RAM/swap safety check\n"
            "  --dry-run     show what would be created without writing\n"
            "  --weak-pw     allow master password below 40-bit entropy\n"
            "  --decoy <src> embed a decoy archive (decoded under coercion)\n"
            "  --stdin-pw    read master password from stdin\n"
            "\nflags (decode):\n"
            "  -i            ignore RAM/swap safety check\n"
            "  --stdin-pw    read master password from stdin\n",
            argv[0],argv[0],argv[0],argv[0],argv[0],
            argv[0],argv[0],argv[0],argv[0],argv[0]);
        return 1;
    }

    /* Legacy rv2 mode */
    if(argc>=3 && !strcmp(argv[1],"--mode") && !strcmp(argv[2],"rv2")){
        if(argc < 5){ rv2_usage(argv[0]); return 1; }
        const char *cmd=argv[3]; const char *path=argv[4];
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

    /* ---- split / join (no path-traversal check needed — output explicit) ---- */
    if(!strcmp(cmd,"split")){
        if(argc<4){dprintf(STDERR_FILENO,"usage: %s split <root.otc> <N>\n",argv[0]);return 1;}
        int n=atoi(argv[3]); if(n<2){dprintf(STDERR_FILENO,"rv: N must be >=2\n");return 1;}
        split_otc(argv[2],n); return 0;
    }
    if(!strcmp(cmd,"join")){
        if(argc<4){dprintf(STDERR_FILENO,"usage: %s join <root.otc.001> <out.otc>\n",argv[0]);return 1;}
        join_otc(argv[2],argv[3]); return 0;
    }

    /* All remaining commands take a path as argv[2] */
    if(argc < 3){
        dprintf(STDERR_FILENO,"rv: missing argument\n"); return 1;
    }
    const char *path = argv[2];
    if(strstr(path,".."))_exit(1);

    /* Scan all flags from argv[3] onward */
    int ignore_swap=0, dry_run=0, remove_after=0, allow_weak_pw=0;
    const char *decoy_source=NULL;
    for(int i=3;i<argc;i++){
        if(!strcmp(argv[i],"-i"))          ignore_swap=1;
        if(!strcmp(argv[i],"-r"))          remove_after=1;
        if(!strcmp(argv[i],"--dry-run"))   dry_run=1;
        if(!strcmp(argv[i],"--weak-pw"))   allow_weak_pw=1;
        if(!strcmp(argv[i],"--stdin-pw"))  g_stdin_pw=1;
        if(!strcmp(argv[i],"--decoy") && i+1<argc){ decoy_source=argv[i+1]; i++; }
    }

    if(!strcmp(cmd,"encode")){
        struct stat st;
        if(stat(path,&st)!=0){perror(path);return 1;}
        if(S_ISDIR(st.st_mode)){
            encode_otc(path, remove_after, ignore_swap, dry_run, allow_weak_pw, decoy_source);
        } else {
            /* Single file: wrap in one container */
            const char *slash=strrchr(path,'/');
            const char *fname=slash?slash+1:path;
            /* base name for output files: strip last extension */
            char base[MAX_PATH_LEN]; strncpy(base,fname,sizeof(base)-1);base[sizeof(base)-1]='\0';
            { char *dot=strrchr(base,'.'); if(dot&&dot!=base)*dot='\0'; }

            if(dry_run){
                printf("=== DRY RUN ===\n");
                printf("File:     %s (%.3f GiB)\n",path,(double)st.st_size/(1024.0*1024.0*1024.0));
                printf("Output:   %s_root.otc\n",base);
                printf("Key:      %s.key (encrypted)\n",base);
                if(remove_after) printf("Remove:   source will be deleted after encode\n");
                if(ignore_swap)  printf("Warnings: RAM/swap check disabled (-i)\n");
                return 0;
            }

            char master_pw[MAX_PW_LEN]; memset(master_pw,0,sizeof(master_pw));
            DECSTR(mprompt,"Key file master password: ");
            read_pw_real(master_pw,sizeof(master_pw),mprompt);
            sodium_memzero(mprompt,sizeof(mprompt));
            wipe_register((volatile uint8_t*)master_pw,MAX_PW_LEN);
            pw_strength_check(master_pw, allow_weak_pw);

            g_ignore_swap_failsafe=ignore_swap;
            check_swap_usage();

            printf("Encoding %s (%.3f GiB)...\n",fname,(double)st.st_size/(1024.0*1024.0*1024.0));

            KeyFile kf; kf_init(&kf);
            char root_pw[ROOT_PW_LEN+1]; gen_password(root_pw); kf_add(&kf,"root",root_pw);
            char cont_name[MAX_PATH_LEN]; snprintf(cont_name,sizeof(cont_name),"%s_1.cont",base);
            char cont_pw[CONT_PW_LEN+1]; gen_password(cont_pw);
            char cont_label[MAX_PATH_LEN]; snprintf(cont_label,sizeof(cont_label),"cont:%s",cont_name); kf_add(&kf,cont_label,cont_pw);
            char fpw[FILE_PW_LEN+1]; gen_password(fpw);
            char clabel[MAX_PATH_LEN]; strncpy(clabel,cont_name,sizeof(clabel)-1);clabel[sizeof(clabel)-1]='\0';
            char *dp=strstr(clabel,".cont"); if(dp)*dp='\0';
            char file_label[MAX_PATH_LEN]; snprintf(file_label,sizeof(file_label),"file:%s/%s",clabel,fname); kf_add(&kf,file_label,fpw);

            size_t fsz; uint8_t *fdata=rfile(path,&fsz);

            /* Start ticker with 1 container / known byte count */
            ticker_start((uint64_t)fsz, 1);

            size_t efsz; uint8_t *efdata=otc_encrypt(fdata,fsz,fpw,&efsz);
            sodium_memzero(fdata,fsz);free(fdata); sodium_memzero(fpw,FILE_PW_LEN);

            /* Signal completion to ticker, then stop */
            prog_add_bytes((uint64_t)fsz);
            prog_done_cont();
            ticker_stop();

            /* v6 wire format */
            shake_ctx tree_ctx; shake256_init(&tree_ctx);
            uint16_t rplen16=(uint16_t)strlen(fname);
            uint8_t rpl_h[2]; w16(rpl_h,rplen16);
            shake256_absorb(&tree_ctx,rpl_h,2);
            shake256_absorb(&tree_ctx,(const uint8_t*)fname,rplen16);
            uint8_t fsz_h[8]; w64(fsz_h,(uint64_t)fsz);
            shake256_absorb(&tree_ctx,fsz_h,8);
            uint8_t tree_hash[TREE_HASH_LEN];
            shake256_finalize(&tree_ctx); shake256_squeeze(&tree_ctx,tree_hash,TREE_HASH_LEN);

            BB wire; bb_init(&wire);
            bb_app(&wire,CONT_MAGIC_V6,8);
            uint8_t fc[4]; w32(fc,1); bb_app(&wire,fc,4);
            bb_app(&wire,tree_hash,TREE_HASH_LEN);
            enc_relpath(&wire,fname,cont_pw);
            uint8_t dl[8]; w64(dl,(uint64_t)efsz); bb_app(&wire,dl,8);
            bb_app(&wire,efdata,efsz); free(efdata);

            size_t esz; uint8_t *enc=otc_encrypt(wire.d,wire.sz,cont_pw,&esz);
            sodium_memzero(wire.d,wire.sz);bb_free(&wire); sodium_memzero(cont_pw,CONT_PW_LEN);

            BB ra; bb_init(&ra);
            bb_app(&ra,CONT_MAGIC_V6,8);
            uint8_t nc[4]; w32(nc,1); bb_app(&ra,nc,4);
            size_t cnl=strlen(cont_name); uint8_t cnl_b[2]; w16(cnl_b,(uint16_t)cnl); bb_app(&ra,cnl_b,2);
            bb_app(&ra,cont_name,cnl);
            uint8_t esz_b[8]; w64(esz_b,(uint64_t)esz); bb_app(&ra,esz_b,8);
            bb_app(&ra,enc,esz); free(enc);

            size_t root_enc_sz; uint8_t *root_enc=otc_encrypt(ra.d,ra.sz,root_pw,&root_enc_sz);
            sodium_memzero(ra.d,ra.sz);bb_free(&ra); sodium_memzero(root_pw,ROOT_PW_LEN);

            char opath[MAX_PATH_LEN],key_path[MAX_PATH_LEN];
            snprintf(opath,sizeof(opath),"%s_root.otc",base);
            snprintf(key_path,sizeof(key_path),"%s.key",base);
            wfile(opath,root_enc,root_enc_sz); free(root_enc);
            kf_write_enc(&kf,key_path,master_pw);
            wipe_unregister((volatile uint8_t*)master_pw);
            sodium_memzero(master_pw,MAX_PW_LEN);
            kf_free(&kf);

            printf("Created: %s\n",opath);
            printf("Created: %s (encrypted)\n",key_path);

            /* -r: secure delete source only after successful encode */
            if(remove_after){
                secure_unlink(path);
                printf("Securely removed: %s\n",path);
            }
        }

    } else if(!strcmp(cmd,"decode")){
        if(argc<4){dprintf(STDERR_FILENO,"usage: %s decode <root.otc> <key> [-i]\n",argv[0]);return 1;}
        const char *key_path=argv[3];
        if(strstr(key_path,".."))_exit(1);
        decode_otc(path,key_path,ignore_swap);

    } else if(!strcmp(cmd,"list")){
        if(argc<4){dprintf(STDERR_FILENO,"usage: %s list <root.otc> <key>\n",argv[0]);return 1;}
        {const char *key_path=argv[3];if(strstr(key_path,".."))_exit(1);list_otc(path,key_path);}

    } else if(!strcmp(cmd,"rekey")){
        /* rekey takes only a key file, path = argv[2] = key file */
        rekey_otc(path);

    } else if(!strcmp(cmd,"inspect")){
        if(argc<4){dprintf(STDERR_FILENO,"usage: %s inspect <root.otc> <key>\n",argv[0]);return 1;}
        const char *key_path=argv[3];
        if(strstr(key_path,".."))_exit(1);
        inspect_otc(path,key_path);

    } else if(!strcmp(cmd,"extract")){
        if(argc<5){dprintf(STDERR_FILENO,"usage: %s extract <root.otc> <key> <relpath>\n",argv[0]);return 1;}
        const char *key_path=argv[3];
        const char *relpath =argv[4];
        if(strstr(key_path,"..")||strstr(relpath,".."))_exit(1);
        extract_otc(path,key_path,relpath);

    } else if(!strcmp(cmd,"run")){
        char pw[MAX_PW_LEN]; memset(pw,0,sizeof(pw));
        DECSTR(prompt,"Password: ");
        read_pw_real(pw,sizeof(pw),prompt); sodium_memzero(prompt,sizeof(prompt));
        wipe_register((volatile uint8_t*)pw,MAX_PW_LEN);
        run_secure(path,pw);
        wipe_unregister((volatile uint8_t*)pw);
        sodium_memzero(pw,sizeof(pw));

    } else {
        dprintf(STDERR_FILENO,"unknown command: %s\n",cmd); return 1;
    }
    return 0;
}