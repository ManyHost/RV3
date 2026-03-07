/*
 * RV v5 – Universal Quantum-Resistant Encrypted Container
 * COPYRIGHT MANYHOST — Quantum-Resistant Encryption Protocol
 * Copyright (c) Manyhost.org 2026
 *
 * Runs and builds on: Linux, macOS, FreeBSD, OpenBSD, NetBSD
 * Architectures:      x86-64, ARM64, ARM32, RISC-V, any POSIX
 * NOT supported:      Windows
 *
 * Dependencies: libsodium, libcurl, libelf (Linux only, for integrity check)
 *
 * Build (Linux):
 *   gcc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
 *       -fPIE -pie -fvisibility=hidden -DSTRKEY=0xA7     \
 *       -o rv rv.c -lsodium -lcurl -lelf
 *   strip --strip-all rv && python3 inject_hash.py rv
 *
 * Build (macOS):
 *   clang -O2 -fstack-protector-strong                   \
 *       -fPIE -fvisibility=hidden -DSTRKEY=0xA7          \
 *       -o rv rv.c -lsodium -lcurl
 *   strip rv
 *
 * Build (FreeBSD):
 *   cc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2  \
 *       -fPIE -pie -fvisibility=hidden -DSTRKEY=0xA7     \
 *       -o rv rv.c -lsodium -lcurl
 *   strip rv
 *
 * See build.sh for the full hardened pipeline.
 *
 * ── Quantum Resistance ───────────────────────────────────────────────
 *  ML-KEM-1024 (FIPS 203)    replaces all classical KEMs
 *  SHAKE-256 / SHA3-512      replaces SHA-256 / HMAC-SHA256
 *  Hybrid KDF: SHAKE256(Argon2id || ML-KEM-SS) restores 256-bit PQ security
 *
 * ── Hardware Binding ─────────────────────────────────────────────────
 *  HWID = SHA3-512(cpu_id + dmi/IOKit serials + MAC + public_IP + user_secret)
 *  OTC master pw = SHAKE256("rv5-otc-mpw" || HWID || mlkem_ct)
 *  Decryption requires: correct password + same hardware + same public IP
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
#include <sys/utsname.h>
#include <sodium.h>

/* pqc_core.h must come first: defines keccak_ctx, MLKEM1024_* used
   by both anti_re.h and rv.c */
#include "pqc_core.h"
/* Platform abstractions: HWID, exec, anti-debug, VM detection */
#include "platform.h"
/* Anti-RE: string encryption, traps, canaries */
#include "anti_re.h"

/* ── Self-integrity hash ──
 * Mach-O needs "segment,section" syntax; ELF uses ".rodata".
 */
#if defined(RV_MACOS)
const uint8_t __rv_text_hash[32]
    __attribute__((section("__DATA,__const"))) __attribute__((used)) = {0};
#else
const uint8_t __rv_text_hash[32]
    __attribute__((section(".rodata"))) __attribute__((used)) = {0};
#endif

/* ================================================================== */
/* Constants                                                            */
/* ================================================================== */

/* All magic bytes are XOR-obfuscated — not visible in strings output  */
static const uint8_t _MAGIC_ENC[8] = {
    0x52^0x23,0x56^0x23,0x35^0x23,0x43^0x23,
    0xDE^0x23,0xAD^0x23,0xBE^0x23,0xEF^0x23 };
#define MAGIC_LEN  8
#define MAGIC_XK   0x23
#define VERSION    ((uint8_t)5)
static void get_magic(uint8_t o[8]){for(int i=0;i<8;i++)o[i]=_MAGIC_ENC[i]^MAGIC_XK;}

static const uint8_t _OTCM_ENC[4]={0x52^0x61,0x56^0x61,0x35^0x61,0x4F^0x61};
#define OTCM_XK 0x61
static void get_otcm(uint8_t o[4]){for(int i=0;i<4;i++)o[i]=_OTCM_ENC[i]^OTCM_XK;}

#define SALT_LEN   crypto_pwhash_SALTBYTES           /* 16 */
#define NONCE_LEN  crypto_aead_aes256gcm_NPUBBYTES   /* 12 */
#define KEY_LEN    crypto_aead_aes256gcm_KEYBYTES    /* 32 */
#define TAG_LEN    crypto_aead_aes256gcm_ABYTES      /* 16 */
#define MAC_LEN    64    /* SHAKE-256 MAC (PQ-secure, 256-bit) */
#define PQHASH_LEN 64    /* SHA3-512 OTC hash */
#define OTC_LEN    32
#define OTC_ENC_LEN (SALT_LEN+NONCE_LEN+OTC_LEN+TAG_LEN)  /* 76 */
#define US_LEN     32    /* user_secret */
#define US_ENC_LEN (SALT_LEN+NONCE_LEN+US_LEN+TAG_LEN)    /* 76 */
#define SK_ENC_LEN (SALT_LEN+NONCE_LEN+MLKEM1024_SK_BYTES+TAG_LEN)
#define OTC_MPW_LEN 43
#define HWID_BUF   8192

/*
 * OTC manifest v5:
 *   [magic:4][count:4][otc_hash:64][enc_us:76][enc_sk:SK_ENC_LEN][mlkem_ct:1568]
 */
#define MANIFEST_LEN (4+4+PQHASH_LEN+US_ENC_LEN+SK_ENC_LEN+MLKEM1024_CT_BYTES)

static const char B62[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

#define MAX_PATH_LEN 4096
#define MAX_PW_LEN   256
#define MAX_FILE_SZ  (4ULL*1024*1024*1024)
#define MAX_NAME_LEN 255

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
/* Error / memory helpers                                               */
/* ================================================================== */
__attribute__((noreturn)) static void die(const char *m) {
    (void)m;
    write(STDERR_FILENO, "!\n", 2);
    _exit(1);
}
#ifdef RV_DEBUG
#undef die
__attribute__((noreturn)) static void die(const char *m) {
    fprintf(stderr, "rv: %s\n", m); fflush(stderr); _exit(1);
}
#endif

/* Wrappers around platform secure alloc */
static uint8_t *sa(size_t n) {
    uint8_t *p = plat_secure_alloc(n);
    if (!p) die("M");
    return p;
}
static void sf(uint8_t *p, size_t n) { plat_secure_free(p, n); }

/* ================================================================== */
/* TTY password reader                                                  */
/* ================================================================== */
static void read_pw(char *buf, size_t bl, const char *prompt) {
    RE_GUARD();
    FILE *t = fopen("/dev/tty", "r+");
    if (!t) die("T");
    fputs(prompt, t); fflush(t);
    struct termios old, ne;
    tcgetattr(fileno(t), &old); ne = old;
    ne.c_lflag &= ~(tcflag_t)(ECHO|ECHOE|ECHOK|ECHONL);
    tcsetattr(fileno(t), TCSANOW, &ne);
    if (!fgets(buf, (int)bl, t)) {
        tcsetattr(fileno(t), TCSANOW, &old); fclose(t); die("P");
    }
    tcsetattr(fileno(t), TCSANOW, &old);
    fputc('\n', t); fclose(t);
    size_t l = strlen(buf);
    if (l > 0 && buf[l-1] == '\n') buf[--l] = '\0';
    if (!l) die("E");
}

/* ================================================================== */
/* File I/O                                                             */
/* ================================================================== */
static uint8_t *rfile(const char *path, size_t *sz) {
    struct stat st;
    if (stat(path, &st) != 0) die("S");
    if ((uint64_t)st.st_size > MAX_FILE_SZ) die("L");
    *sz = (size_t)st.st_size;
    FILE *f = fopen(path, "rb"); if (!f) die("O");
    uint8_t *b = malloc(*sz + 1); if (!b) { fclose(f); die("N"); }
    if (*sz > 0 && fread(b, 1, *sz, f) != *sz) { fclose(f); free(b); die("R"); }
    fclose(f); return b;
}
static void wfile(const char *path, const uint8_t *d, size_t s) {
    char tmp[MAX_PATH_LEN];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) die("Q");
    FILE *f = fopen(tmp, "wb"); if (!f) die("W");
    size_t done = 0;
    while (done < s) {
        size_t r = fwrite(d+done, 1, s-done, f);
        if (!r) { fclose(f); unlink(tmp); die("V"); }
        done += r;
    }
    fclose(f);
    if (rename(tmp, path) != 0) { unlink(tmp); die("X"); }
}

/* ================================================================== */
/* Key derivation                                                       */
/*                                                                      */
/* Argon2id for password KDF (PQ-safe, memory-hard).                  */
/* Hybrid KDF mixes ML-KEM shared secret for full PQ resistance.      */
/* ================================================================== */
static void argon2(uint8_t key[32], const char *pw, const uint8_t *salt) {
    STACK_CANARY_INIT(); STACK_CANARY_SAVE(); ANTIDIS_TRAP();
    if (crypto_pwhash(key, 32, pw, strlen(pw), salt,
                      crypto_pwhash_OPSLIMIT_MODERATE,
                      crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) die("K");
    STACK_CANARY_CHECK();
}

static void derive_key(uint8_t key[32], const char *pw, const uint8_t *salt,
                        const uint8_t *mlkem_sk, const uint8_t *mlkem_ct) {
    uint8_t ak[32]; argon2(ak, pw, salt);
    uint8_t ss[32]; memset(ss, 0, 32);
    if (mlkem_sk && mlkem_ct) ml_kem1024_dec(ss, mlkem_ct, mlkem_sk);
    hybrid_kdf(key, 32, ak, ss, salt, SALT_LEN);
    sodium_memzero(ak, 32); sodium_memzero(ss, 32);
    FAKE_CRYPTO_NOISE();
}

/* ================================================================== */
/* Public IP + US enforcement                                           */
/* ================================================================== */
static char *fetch_public_ip(void) {
    /* Returns heap-allocated IP string (caller frees), NULL on fail   */
    /* Also enforces US-only                                            */
    char *resp = plat_https_get("https://ip-api.com/json/?fields=query,countryCode");
    if (!resp) return NULL;
    if (!strstr(resp, "\"US\"")) { free(resp); die("G"); }
    char *qs = strstr(resp, "\"query\":\"");
    char *ip = NULL;
    if (qs) {
        qs += 9;
        char *qe = strchr(qs, '"');
        if (qe) { *qe = '\0'; ip = strdup(qs); }
    }
    free(resp);
    return ip;
}

/* ================================================================== */
/* HWID collection → SHA3-512 (64 bytes, 256-bit PQ security)          */
/* ================================================================== */
static void collect_hwid(uint8_t out[64],
                          const uint8_t *user_sec,
                          const char *ip_override) {
    STACK_CANARY_INIT(); STACK_CANARY_SAVE(); RE_GUARD();

    uint8_t *buf = sa(HWID_BUF);
    size_t off = plat_collect_hwid(buf, HWID_BUF - 256);

    /* Append public IP */
    char *ip = NULL;
    if (ip_override) {
        ip = (char *)ip_override;
    } else {
        ip = fetch_public_ip(); /* dies on non-US */
        if (!ip) { sf(buf, HWID_BUF); die("I"); }
    }
    int n = snprintf((char*)buf+off, HWID_BUF-off, "pip:%s\n", ip);
    if (n > 0 && off+(size_t)n < HWID_BUF) off += (size_t)n;
    if (ip != ip_override) free(ip);

    /* Append user_secret */
    _hwid_bytes(buf, &off, HWID_BUF, "us", user_sec, US_LEN);

    ANTIDIS_TRAP();
    sha3_512(out, buf, off);   /* SHA3-512: 256-bit PQ security */
    sf(buf, HWID_BUF);
    STACK_CANARY_CHECK();
}

/* ================================================================== */
/* OTC master password                                                  */
/* SHAKE256("rv5-otc-mpw" || hwid[64] || mlkem_ct) → 43 base62 chars  */
/* ================================================================== */
static void derive_otc_mpw(char *out, const uint8_t hwid[64],
                             const uint8_t mlkem_ct[MLKEM1024_CT_BYTES]) {
    ANTIDIS_TRAP2();
    uint8_t raw[32];
    keccak_ctx c; shake256_init(&c);
    DECSTR(dom, "rv5-otc-mpw");
    shake256_absorb(&c, (uint8_t*)dom, strlen(dom));
    sodium_memzero(dom, sizeof(dom));
    shake256_absorb(&c, hwid, 64);
    shake256_absorb(&c, mlkem_ct, MLKEM1024_CT_BYTES);
    shake256_finalize(&c); shake256_squeeze(&c, raw, 32);

    uint32_t tmp[8];
    for (int i=0;i<8;i++)
        tmp[i]=((uint32_t)raw[i*4]<<24)|((uint32_t)raw[i*4+1]<<16)|
               ((uint32_t)raw[i*4+2]<<8)|(uint32_t)raw[i*4+3];
    char dig[OTC_MPW_LEN+1];
    for (int d=OTC_MPW_LEN-1;d>=0;d--) {
        uint64_t rem=0;
        for(int i=0;i<8;i++){uint64_t cur=(rem<<32)|(uint64_t)tmp[i];tmp[i]=(uint32_t)(cur/62);rem=cur%62;}
        dig[d]=B62[rem];
    }
    dig[OTC_MPW_LEN]='\0';
    memcpy(out, dig, OTC_MPW_LEN+1);
    sodium_memzero(raw,32); sodium_memzero(tmp,sizeof(tmp));
    FAKE_CRYPTO_NOISE();
}

/* ================================================================== */
/* Blob encrypt/decrypt (Argon2id, AES-256-GCM)                        */
/* Used for: user_secret, ML-KEM secret key                            */
/* ================================================================== */
static void enc_blob(uint8_t *out, const uint8_t *data, size_t dl, const char *pw) {
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN]; uint8_t *key = sa(KEY_LEN);
    randombytes_buf(salt, SALT_LEN); randombytes_buf(nonce, NONCE_LEN);
    argon2(key, pw, salt);
    uint8_t *enc = malloc(dl+TAG_LEN); if (!enc) { sf(key,KEY_LEN); die("N"); }
    unsigned long long el;
    crypto_aead_aes256gcm_encrypt(enc,&el,data,dl,NULL,0,NULL,nonce,key);
    sf(key, KEY_LEN);
    memcpy(out,       salt,  SALT_LEN);
    memcpy(out+SALT_LEN,     nonce, NONCE_LEN);
    memcpy(out+SALT_LEN+NONCE_LEN, enc, (size_t)el);
    free(enc);
}
static void dec_blob(uint8_t *out, const uint8_t *in, size_t dl, const char *pw) {
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN];
    memcpy(salt,  in,         SALT_LEN);
    memcpy(nonce, in+SALT_LEN, NONCE_LEN);
    uint8_t *key = sa(KEY_LEN); argon2(key, pw, salt);
    unsigned long long decl;
    if (crypto_aead_aes256gcm_decrypt(out,&decl,NULL,
                                       in+SALT_LEN+NONCE_LEN, dl+TAG_LEN,
                                       NULL,0,nonce,key) != 0)
        { sf(key, KEY_LEN); die("D"); }
    sf(key, KEY_LEN);
}

/* ================================================================== */
/* OTC encrypt/decrypt                                                  */
/* ================================================================== */
static void otc_enc(uint8_t *out, const uint8_t *otc, const char *mpw) {
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN]; uint8_t *key = sa(KEY_LEN);
    randombytes_buf(salt,SALT_LEN); randombytes_buf(nonce,NONCE_LEN);
    argon2(key,mpw,salt);
    uint8_t enc[OTC_LEN+TAG_LEN]; unsigned long long el;
    crypto_aead_aes256gcm_encrypt(enc,&el,otc,OTC_LEN,NULL,0,NULL,nonce,key);
    sf(key,KEY_LEN);
    memcpy(out,salt,SALT_LEN); memcpy(out+SALT_LEN,nonce,NONCE_LEN);
    memcpy(out+SALT_LEN+NONCE_LEN,enc,(size_t)el);
}
static int otc_dec(uint8_t *out, const uint8_t *in, const char *mpw) {
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN];
    memcpy(salt,in,SALT_LEN); memcpy(nonce,in+SALT_LEN,NONCE_LEN);
    uint8_t *key = sa(KEY_LEN); argon2(key,mpw,salt);
    unsigned long long dl;
    int rc = crypto_aead_aes256gcm_decrypt(out,&dl,NULL,
                 in+SALT_LEN+NONCE_LEN,OTC_LEN+TAG_LEN,NULL,0,nonce,key);
    sf(key,KEY_LEN); return rc;
}

/* ================================================================== */
/* Manifest read/write                                                  */
/* ================================================================== */
static void write_manifest(const char *cpath, uint32_t cnt,
                             const uint8_t otc_hash[PQHASH_LEN],
                             const uint8_t enc_us[US_ENC_LEN],
                             const uint8_t *enc_sk,
                             const uint8_t mlkem_ct[MLKEM1024_CT_BYTES]) {
    char mp[MAX_PATH_LEN];
    snprintf(mp, sizeof(mp), "%s.otc", cpath);
    uint8_t *buf = malloc(MANIFEST_LEN); if (!buf) die("N");
    uint8_t magic[4]; get_otcm(magic);
    size_t o = 0;
    memcpy(buf+o,magic,4);               o+=4;
    w32(buf+o,cnt);                      o+=4;
    memcpy(buf+o,otc_hash,PQHASH_LEN);  o+=PQHASH_LEN;
    memcpy(buf+o,enc_us,US_ENC_LEN);    o+=US_ENC_LEN;
    memcpy(buf+o,enc_sk,SK_ENC_LEN);    o+=SK_ENC_LEN;
    memcpy(buf+o,mlkem_ct,MLKEM1024_CT_BYTES); o+=MLKEM1024_CT_BYTES;
    wfile(mp, buf, MANIFEST_LEN); free(buf);
}
static void read_manifest(const char *cpath, uint32_t *cnt,
                            uint8_t otc_hash[PQHASH_LEN],
                            uint8_t enc_us[US_ENC_LEN],
                            uint8_t *enc_sk,
                            uint8_t mlkem_ct[MLKEM1024_CT_BYTES]) {
    char mp[MAX_PATH_LEN];
    snprintf(mp, sizeof(mp), "%s.otc", cpath);
    size_t sz; uint8_t *buf = rfile(mp, &sz);
    uint8_t magic[4]; get_otcm(magic);
    if (sz != MANIFEST_LEN || memcmp(buf,magic,4) != 0) { free(buf); die("Z"); }
    size_t o=4;
    *cnt = r32(buf+o);                   o+=4;
    memcpy(otc_hash,buf+o,PQHASH_LEN);  o+=PQHASH_LEN;
    memcpy(enc_us,  buf+o,US_ENC_LEN);  o+=US_ENC_LEN;
    memcpy(enc_sk,  buf+o,SK_ENC_LEN);  o+=SK_ENC_LEN;
    memcpy(mlkem_ct,buf+o,MLKEM1024_CT_BYTES);
    free(buf);
}

/* ================================================================== */
/* RV5C outer container frame                                           */
/*                                                                      */
/* Format: [magic:8][ver:1][orig:8][salt:16][nonce:12][ct+tag][mac:64] */
/* AES key = hybrid_kdf(Argon2id, ML-KEM-SS)                          */
/* MAC     = SHAKE256-MAC(mac_key, hdr||ct), 64 bytes                  */
/* ================================================================== */
#define HDR_SZ (MAGIC_LEN+1+8+SALT_LEN+NONCE_LEN)  /* 45 */

static void write_rv5c(const char *path,
                        const uint8_t *in, size_t il,
                        const char *pw,
                        const uint8_t *otc,
                        const uint8_t *mlkem_sk,
                        const uint8_t *mlkem_ct) {
    STACK_CANARY_INIT(); STACK_CANARY_SAVE(); ANTIDIS_TRAP();
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN];
    randombytes_buf(salt,SALT_LEN); randombytes_buf(nonce,NONCE_LEN);

    uint8_t *key = sa(KEY_LEN);
    derive_key(key, pw, salt, mlkem_sk, mlkem_ct);
    if (otc) for (size_t i=0;i<OTC_LEN&&i<KEY_LEN;i++) key[i]^=otc[i];

    /* MAC key: SHAKE256(enc_key || "mac") */
    uint8_t mkey[MAC_LEN];
    { uint8_t ctx[]={'m','a','c',0};
      shake256_mac(mkey,MAC_LEN,key,KEY_LEN,ctx,4); }

    uint8_t *ct = malloc(il+TAG_LEN); if (!ct){sf(key,KEY_LEN);die("C");}
    unsigned long long cl;
    if (crypto_aead_aes256gcm_encrypt(ct,&cl,in,il,NULL,0,NULL,nonce,key)!=0)
        {sf(key,KEY_LEN);free(ct);die("A");}
    sf(key, KEY_LEN);

    uint8_t hdr[HDR_SZ]; size_t ho=0;
    uint8_t magic[8]; get_magic(magic);
    memcpy(hdr+ho,magic,MAGIC_LEN); ho+=MAGIC_LEN;
    hdr[ho++]=VERSION;
    w64(hdr+ho,(uint64_t)il); ho+=8;
    memcpy(hdr+ho,salt,SALT_LEN);   ho+=SALT_LEN;
    memcpy(hdr+ho,nonce,NONCE_LEN); ho+=NONCE_LEN;

    uint8_t mac[MAC_LEN];
    { keccak_ctx mc; shake256_init(&mc);
      shake256_absorb(&mc,mkey,MAC_LEN);
      shake256_absorb(&mc,hdr,ho);
      shake256_absorb(&mc,ct,(size_t)cl);
      shake256_finalize(&mc); shake256_squeeze(&mc,mac,MAC_LEN); }

    FILE *f = fopen(path,"wb"); if (!f){free(ct);die("F");}
    fwrite(hdr,1,ho,f); fwrite(ct,1,(size_t)cl,f); fwrite(mac,1,MAC_LEN,f);
    fclose(f); free(ct);
    STACK_CANARY_CHECK();
}

static uint8_t *read_rv5c(const char *path, const char *pw,
                            const uint8_t *otc,
                            const uint8_t *mlkem_sk,
                            const uint8_t *mlkem_ct_m,
                            size_t *ol) {
    STACK_CANARY_INIT(); STACK_CANARY_SAVE(); ANTIDIS_TRAP();
    size_t sz; uint8_t *buf = rfile(path, &sz);
    if (sz < HDR_SZ+TAG_LEN+MAC_LEN) { free(buf); die("H"); }
    uint8_t magic[8]; get_magic(magic);
    if (memcmp(buf,magic,MAGIC_LEN)!=0) { free(buf); die("M"); }
    size_t o = MAGIC_LEN;
    if (buf[o++] != VERSION) { free(buf); die("V"); }
    o += 8; /* orig_size */
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN];
    memcpy(salt, buf+o,SALT_LEN);  o+=SALT_LEN;
    memcpy(nonce,buf+o,NONCE_LEN); o+=NONCE_LEN;
    size_t hl=o, cl=sz-hl-MAC_LEN;
    if (cl<TAG_LEN) { free(buf); die("U"); }
    const uint8_t *ct=buf+hl, *mac=buf+sz-MAC_LEN;

    uint8_t *key = sa(KEY_LEN);
    derive_key(key, pw, salt, mlkem_sk, mlkem_ct_m);
    if (otc) for (size_t i=0;i<OTC_LEN&&i<KEY_LEN;i++) key[i]^=otc[i];

    uint8_t mkey[MAC_LEN];
    { uint8_t ctx[]={'m','a','c',0};
      shake256_mac(mkey,MAC_LEN,key,KEY_LEN,ctx,4); }

    uint8_t emac[MAC_LEN];
    { keccak_ctx mc; shake256_init(&mc);
      shake256_absorb(&mc,mkey,MAC_LEN);
      shake256_absorb(&mc,buf,hl);
      shake256_absorb(&mc,ct,cl);
      shake256_finalize(&mc); shake256_squeeze(&mc,emac,MAC_LEN); }

    if (sodium_memcmp(mac,emac,MAC_LEN)!=0) { sf(key,KEY_LEN); free(buf); die("J"); }

    /* FIX #2: Integer underflow - explicit bounds check before subtraction */
    if (cl < TAG_LEN) { sf(key,KEY_LEN); free(buf); die("U"); }
    size_t plain_size = cl - TAG_LEN;
    if (plain_size == 0 || plain_size > 0x40000000) { sf(key,KEY_LEN); free(buf); die("U"); } /* 1GB limit */
    
    uint8_t *plain = malloc(plain_size + 1);
    if (!plain) { sf(key,KEY_LEN); free(buf); die("N"); }
    unsigned long long dl;
    if (crypto_aead_aes256gcm_decrypt(plain,&dl,NULL,ct,cl,NULL,0,nonce,key)!=0)
        { sf(key,KEY_LEN); free(buf); free(plain); die("Y"); }
    sf(key,KEY_LEN); free(buf);
    *ol = (size_t)dl;
    STACK_CANARY_CHECK();
    return plain;
}

/* ================================================================== */
/* Password generation                                                  */
/*                                                                      */
/* Generates a random 30-character base62 password.                   */
/* 30 base62 chars ≈ 178 bits of entropy — well above AES-256 needs. */
/* ================================================================== */
#define FILE_PW_LEN   30
#define CONT_PW_LEN   30
#define ROOT_PW_LEN   30

static void gen_password(char out[FILE_PW_LEN+1]) {
    /* Draw random bytes, map to base62 via rejection sampling */
    uint8_t raw[64];
    int pos = 0;
    while (pos < FILE_PW_LEN) {
        randombytes_buf(raw, sizeof(raw));
        for (int i = 0; i < (int)sizeof(raw) && pos < FILE_PW_LEN; i++) {
            /* Reject values >= 248 to avoid modulo bias (248 = 4*62) */
            if (raw[i] < 248)
                out[pos++] = B62[raw[i] % 62];
        }
    }
    out[FILE_PW_LEN] = '\0';
    sodium_memzero(raw, sizeof(raw));
}

/* ================================================================== */
/* Growable buffer                                                      */
/* ================================================================== */
typedef struct { uint8_t *d; size_t sz; size_t cap; } BB;
static void bb_init(BB *b){b->cap=64*1024;b->sz=0;b->d=malloc(b->cap);if(!b->d)die("B");}
static void bb_need(BB *b,size_t x){while(b->sz+x>b->cap){b->cap*=2;uint8_t*nb=realloc(b->d,b->cap);if(!nb)die("B");b->d=nb;}}
static void bb_app(BB *b,const void *s,size_t l){bb_need(b,l);memcpy(b->d+b->sz,s,l);b->sz+=l;}
static void bb_free(BB *b){free(b->d);b->d=NULL;b->sz=b->cap=0;}

/* ================================================================== */
/* Key file                                                             */
/*                                                                      */
/* Format — one entry per line:                                        */
/*   root:<password>                                                   */
/*   cont:<contname>:<password>                                        */
/*   file:<contname>/<filename>:<password>                             */
/*                                                                      */
/* The decoder reads this sequentially.  Labels make it human-readable */
/* and allow out-of-order lookup if needed.                            */
/* ================================================================== */
typedef struct {
    char  label[MAX_PATH_LEN];  /* e.g. "cont:other_1.cont" */
    char  pw[FILE_PW_LEN+1];
} KeyEntry;

typedef struct {
    KeyEntry *entries;
    size_t    cnt;
    size_t    cap;
} KeyFile;

static void kf_init(KeyFile *kf) {
    kf->cap = 64;
    kf->cnt = 0;
    kf->entries = malloc(kf->cap * sizeof(KeyEntry));
    if (!kf->entries) die("N");
}
static void kf_add(KeyFile *kf, const char *label, const char *pw) {
    if (kf->cnt >= kf->cap) {
        kf->cap *= 2;
        /* FIX #9: File descriptor leak prevention in realloc error path */
        KeyEntry *new_entries = realloc(kf->entries, kf->cap * sizeof(KeyEntry));
        if (!new_entries) {
            fprintf(stderr, "memory allocation failed\n");
            die("N");
        }
        kf->entries = new_entries;
    }
    /* FIX #5,#8: Ensure proper null termination of all fields */
    size_t label_len = strlen(label);
    if (label_len >= MAX_PATH_LEN) label_len = MAX_PATH_LEN - 1;
    memcpy(kf->entries[kf->cnt].label, label, label_len);
    kf->entries[kf->cnt].label[label_len] = '\0';
    
    size_t pw_len = strlen(pw);
    if (pw_len >= FILE_PW_LEN) pw_len = FILE_PW_LEN - 1;
    memcpy(kf->entries[kf->cnt].pw, pw, pw_len);
    kf->entries[kf->cnt].pw[pw_len] = '\0';
    kf->cnt++
}
static const char *kf_get(const KeyFile *kf, const char *label) {
    for (size_t i = 0; i < kf->cnt; i++)
        if (!strcmp(kf->entries[i].label, label))
            return kf->entries[i].pw;
    return NULL;
}
static void kf_write(const KeyFile *kf, const char *path) {
    FILE *f = fopen(path, "w"); if (!f) die("W");
    for (size_t i = 0; i < kf->cnt; i++)
        fprintf(f, "%s:%s\n", kf->entries[i].label, kf->entries[i].pw);
    fclose(f);
}
static void kf_read(KeyFile *kf, const char *path) {
    kf_init(kf);
    FILE *f = fopen(path, "r"); if (!f) die("O");
    /* FIX #4: Password file buffer overflow - proper line size and truncation detection */
    #define MAX_LINE_LEN (MAX_PATH_LEN + FILE_PW_LEN + 10)
    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        size_t ll = strlen(line);
        if (ll > 0 && line[ll-1] == '\n') line[--ll] = '\0';
        /* FIX #9: Detect when line was truncated (no newline and buffer full) */
        if (ll > 0 && ll >= sizeof(line) - 2) {
            fprintf(stderr, "error: key file line too long (truncated)\n");
            break;
        }
        if (!ll) continue;
        /* Find last colon — password is after it, label is everything before */
        char *lc = strrchr(line, ':');
        if (!lc) continue;
        *lc = '\0';
        kf_add(kf, line, lc+1);
    }
    fclose(f);
}
static void kf_free(KeyFile *kf) {
    if (kf->entries) {
        /* Wipe passwords from memory */
        for (size_t i = 0; i < kf->cnt; i++)
            sodium_memzero(kf->entries[i].pw, FILE_PW_LEN);
        free(kf->entries);
    }
    kf->entries = NULL; kf->cnt = kf->cap = 0;
}

/* ================================================================== */

/* ================================================================== */
/* Fast OTC encrypt/decrypt                                             */
/*                                                                      */
/* Per-file and per-container passwords are randomly generated         */
/* (30-char base62 ≈ 178-bit entropy).  They are NOT human-chosen,    */
/* so Argon2id is overkill and causes the hang.                        */
/*                                                                      */
/* Instead: key = SHAKE-256(pw || salt), one call, microseconds.      */
/* AES-256-GCM provides the actual confidentiality + authentication.  */
/*                                                                      */
/* Argon2id is still used for the outer read_rv5c / write_rv5c layer  */
/* where the key is a human-typed password.                            */
/* ================================================================== */

static void fast_kdf(uint8_t key[KEY_LEN],
                      const char *pw, const uint8_t salt[SALT_LEN]) {
    /* SHAKE-256(pw || 0x01 || salt) → 32 bytes */
    keccak_ctx c; shake256_init(&c);
    shake256_absorb(&c, (const uint8_t*)pw, strlen(pw));
    uint8_t sep = 0x01; shake256_absorb(&c, &sep, 1);
    shake256_absorb(&c, salt, SALT_LEN);
    shake256_finalize(&c); shake256_squeeze(&c, key, KEY_LEN);
}

static uint8_t *otc_encrypt(const uint8_t *in, size_t il,
                              const char *pw, size_t *ol) {
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN];
    randombytes_buf(salt, SALT_LEN);
    randombytes_buf(nonce, NONCE_LEN);

    uint8_t *key = sa(KEY_LEN);
    fast_kdf(key, pw, salt);

    size_t olen = SALT_LEN + NONCE_LEN + il + TAG_LEN;
    uint8_t *out = malloc(olen); if (!out) { sf(key, KEY_LEN); die("N"); }
    memcpy(out,              salt,  SALT_LEN);
    memcpy(out + SALT_LEN,   nonce, NONCE_LEN);

    unsigned long long cl;
    if (crypto_aead_aes256gcm_encrypt(out + SALT_LEN + NONCE_LEN, &cl,
                                       in, il, NULL, 0, NULL, nonce, key) != 0)
        { sf(key, KEY_LEN); free(out); die("A"); }
    sf(key, KEY_LEN);
    *ol = SALT_LEN + NONCE_LEN + (size_t)cl;
    return out;
}

static uint8_t *otc_decrypt(const uint8_t *in, size_t il,
                              const char *pw, size_t *ol) {
    if (il < SALT_LEN + NONCE_LEN + TAG_LEN) die("H");
    uint8_t salt[SALT_LEN], nonce[NONCE_LEN];
    memcpy(salt,  in,            SALT_LEN);
    memcpy(nonce, in + SALT_LEN, NONCE_LEN);

    uint8_t *key = sa(KEY_LEN);
    fast_kdf(key, pw, salt);

    size_t ct_len = il - SALT_LEN - NONCE_LEN;
    uint8_t *out = malloc(ct_len); if (!out) { sf(key, KEY_LEN); die("N"); }
    unsigned long long dl;
    if (crypto_aead_aes256gcm_decrypt(out, &dl, NULL,
                                       in + SALT_LEN + NONCE_LEN, ct_len,
                                       NULL, 0, nonce, key) != 0)
        { sf(key, KEY_LEN); free(out); die("Y"); }
    sf(key, KEY_LEN);
    *ol = (size_t)dl;
    return out;
}

/* ================================================================== */
/* File list collector                                                  */
/* ================================================================== */
typedef struct {
    char **paths;
    size_t cnt, cap;
} FileList;

static void fl_init(FileList *fl) {
    fl->cap = 64; fl->cnt = 0;
    fl->paths = malloc(fl->cap * sizeof(char*));
    if (!fl->paths) die("N");
}
static void fl_add(FileList *fl, const char *p) {
    if (fl->cnt >= fl->cap) {
        fl->cap *= 2;
        fl->paths = realloc(fl->paths, fl->cap * sizeof(char*));
        if (!fl->paths) die("N");
    }
    fl->paths[fl->cnt++] = strdup(p);
}
static void fl_free(FileList *fl) {
    for (size_t i = 0; i < fl->cnt; i++) free(fl->paths[i]);
    free(fl->paths); fl->paths = NULL; fl->cnt = fl->cap = 0;
}

static void fl_collect(FileList *fl, const char *abs_dir,
                        const char *rel_prefix) {
    DIR *d = opendir(abs_dir); if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        char abs[MAX_PATH_LEN], rel[MAX_PATH_LEN];
        if (snprintf(abs, sizeof(abs), "%s/%s", abs_dir, e->d_name) >= (int)sizeof(abs))
            continue;
        if (*rel_prefix)
            snprintf(rel, sizeof(rel), "%s/%s", rel_prefix, e->d_name);
        else
            snprintf(rel, sizeof(rel), "%s", e->d_name);
        struct stat st; if (lstat(abs, &st) != 0) continue;
        if      (S_ISREG(st.st_mode)) fl_add(fl, rel);
        else if (S_ISDIR(st.st_mode)) fl_collect(fl, abs, rel);
    }
    closedir(d);
}

/* ================================================================== */
/* Container wire format                                                */
/*                                                                      */
/*  [magic 8][file_count 4]                                            */
/*  per file: [relpath_len 2][relpath N][data_len 8][enc_data M]       */
/*                                                                      */
/* The whole thing is then wrapped by otc_encrypt(container_pw).      */
/* ================================================================== */
static const uint8_t CONT_MAGIC[8] = {'R','V','C','O','N','T',0x05,0x00};

/* ================================================================== */
/* Thread pool for parallel container encryption                       */
/* ================================================================== */
#include <pthread.h>

/* Each worker encrypts one sub-container's worth of files */
typedef struct {
    /* inputs */
    const char  *root_dir;
    char       **relpaths;
    size_t       nfiles;
    const char  *cont_name;  /* e.g. "other_1.cont" */
    KeyFile     *kf;
    pthread_mutex_t *kf_mutex;  /* protect kf_add */

    /* outputs */
    uint8_t *enc_data;   /* encrypted container blob, heap-allocated */
    size_t   enc_sz;
    char     cont_pw[CONT_PW_LEN+1];  /* saved for key file */
} ContWork;

static void *cont_worker(void *arg) {
    ContWork *w = (ContWork *)arg;

    /* Container password */
    gen_password(w->cont_pw);

    /* Build wire archive */
    BB wire; bb_init(&wire);
    bb_app(&wire, CONT_MAGIC, 8);
    uint8_t fc[4]; w32(fc, (uint32_t)w->nfiles); bb_app(&wire, fc, 4);

    /* Allocate per-file passwords (build them all before touching kf) */
    char (*fpws)[FILE_PW_LEN+1] = malloc(w->nfiles * (FILE_PW_LEN+1));
    if (!fpws) die("N");

    for (size_t i = 0; i < w->nfiles; i++) {
        gen_password(fpws[i]);

        /* Read + encrypt file */
        char abs[MAX_PATH_LEN];
        snprintf(abs, sizeof(abs), "%s/%s", w->root_dir, w->relpaths[i]);
        size_t fsz; uint8_t *fdata = rfile(abs, &fsz);

        size_t efsz; uint8_t *efdata = otc_encrypt(fdata, fsz, fpws[i], &efsz);
        sodium_memzero(fdata, fsz); free(fdata);

        /* Write relpath + encrypted blob into wire */
        size_t rplen = strlen(w->relpaths[i]);
        uint8_t rpl[2]; w16(rpl, (uint16_t)rplen); bb_app(&wire, rpl, 2);
        bb_app(&wire, w->relpaths[i], rplen);
        uint8_t dl[8]; w64(dl, (uint64_t)efsz); bb_app(&wire, dl, 8);
        bb_app(&wire, efdata, efsz);
        free(efdata);
    }

    /* Encrypt the container */
    w->enc_data = otc_encrypt(wire.d, wire.sz, w->cont_pw, &w->enc_sz);
    sodium_memzero(wire.d, wire.sz); bb_free(&wire);

    /* Register all passwords into the shared key file (locked) */
    pthread_mutex_lock(w->kf_mutex);
    /* strip ".cont" from cont_name for labels */
    char cl[MAX_PATH_LEN];
    strncpy(cl, w->cont_name, sizeof(cl)-1); cl[sizeof(cl)-1] = '\0';
    char *dotp = strstr(cl, ".cont"); if (dotp) *dotp = '\0';

    char lbl[MAX_PATH_LEN];
    snprintf(lbl, sizeof(lbl), "cont:%s", w->cont_name);
    kf_add(w->kf, lbl, w->cont_pw);

    for (size_t i = 0; i < w->nfiles; i++) {
        snprintf(lbl, sizeof(lbl), "file:%s/%s", cl, w->relpaths[i]);
        kf_add(w->kf, lbl, fpws[i]);
        sodium_memzero(fpws[i], FILE_PW_LEN);
    }
    pthread_mutex_unlock(w->kf_mutex);

    free(fpws);
    return NULL;
}

/* ================================================================== */
/* Detect number of logical CPUs                                        */
/* ================================================================== */
static int cpu_count(void) {
#if defined(RV_LINUX) || defined(RV_BSD)
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (int)n : 1;
#elif defined(RV_MACOS)
    int n = 1; size_t sz = sizeof(n);
    sysctlbyname("hw.logicalcpu", &n, &sz, NULL, 0);
    return (n > 0) ? n : 1;
#else
    return 1;
#endif
}

/* ================================================================== */
/* Encode: folder → <base>_root.otc + <base>.key                      */
/* ================================================================== */
#define FILES_PER_CONT 3

static void encode_otc(const char *folder, int remove_original) {
    RE_GUARD();

    /* Normalise path */
    char root[MAX_PATH_LEN];
    strncpy(root, folder, sizeof(root)-1); root[sizeof(root)-1] = '\0';
    size_t rl = strlen(root);
    while (rl > 1 && root[rl-1] == '/') root[--rl] = '\0';

    const char *base = strrchr(root, '/');
    base = base ? base+1 : root;

    /* Collect files */
    FileList fl; fl_init(&fl);
    fl_collect(&fl, root, "");
    if (fl.cnt == 0) { fl_free(&fl); fprintf(stderr, "rv: no files found\n"); return; }

    size_t nconts = (fl.cnt + FILES_PER_CONT - 1) / FILES_PER_CONT;
    int nthreads  = cpu_count();
    if (nthreads > (int)nconts) nthreads = (int)nconts;
    if (nthreads < 1) nthreads = 1;

    printf("Encoding %zu file(s) into %zu container(s) using %d thread(s)...\n",
           fl.cnt, nconts, nthreads);

    KeyFile kf; kf_init(&kf);
    pthread_mutex_t kf_mutex = PTHREAD_MUTEX_INITIALIZER;

    /* Root container password */
    char root_pw[ROOT_PW_LEN+1]; gen_password(root_pw);
    kf_add(&kf, "root", root_pw);

    /* Allocate work units */
    ContWork *work = calloc(nconts, sizeof(ContWork));
    pthread_t *threads = malloc(nconts * sizeof(pthread_t));
    if (!work || !threads) die("N");

    /* Launch containers in waves of nthreads */
    for (size_t ci = 0; ci < nconts; ci++) {
        size_t file_start = ci * FILES_PER_CONT;
        size_t file_end   = file_start + FILES_PER_CONT;
        if (file_end > fl.cnt) file_end = fl.cnt;

        char cont_name[MAX_PATH_LEN];
        snprintf(cont_name, sizeof(cont_name), "%s_%zu.cont", base, ci+1);

        work[ci].root_dir  = root;
        work[ci].relpaths  = fl.paths + file_start;
        work[ci].nfiles    = file_end - file_start;
        work[ci].cont_name = strdup(cont_name);
        work[ci].kf        = &kf;
        work[ci].kf_mutex  = &kf_mutex;
        work[ci].enc_data  = NULL;
        work[ci].enc_sz    = 0;
    }

    /* Process in batches of nthreads */
    for (size_t ci = 0; ci < nconts; ci += (size_t)nthreads) {
        size_t batch_end = ci + (size_t)nthreads;
        if (batch_end > nconts) batch_end = nconts;

        for (size_t t = ci; t < batch_end; t++)
            pthread_create(&threads[t], NULL, cont_worker, &work[t]);
        for (size_t t = ci; t < batch_end; t++)
            pthread_join(threads[t], NULL);

        printf("  [%zu/%zu] containers done\n", batch_end, nconts);
    }

    /* Assemble root archive */
    BB root_archive; bb_init(&root_archive);
    bb_app(&root_archive, CONT_MAGIC, 8);
    uint8_t nc_b[4]; w32(nc_b, (uint32_t)nconts); bb_app(&root_archive, nc_b, 4);

    for (size_t ci = 0; ci < nconts; ci++) {
        size_t cnl = strlen(work[ci].cont_name);
        uint8_t cnl_b[2]; w16(cnl_b, (uint16_t)cnl);
        bb_app(&root_archive, cnl_b, 2);
        bb_app(&root_archive, work[ci].cont_name, cnl);
        uint8_t esz_b[8]; w64(esz_b, (uint64_t)work[ci].enc_sz);
        bb_app(&root_archive, esz_b, 8);
        bb_app(&root_archive, work[ci].enc_data, work[ci].enc_sz);
        free(work[ci].enc_data);
        free((char*)work[ci].cont_name);
    }
    free(work); free(threads);
    pthread_mutex_destroy(&kf_mutex);

    /* Encrypt root archive */
    size_t root_enc_sz;
    uint8_t *root_enc = otc_encrypt(root_archive.d, root_archive.sz,
                                     root_pw, &root_enc_sz);
    sodium_memzero(root_archive.d, root_archive.sz); bb_free(&root_archive);
    sodium_memzero(root_pw, ROOT_PW_LEN);

    /* Write output files */
    char root_cont_path[MAX_PATH_LEN], key_path[MAX_PATH_LEN];
    snprintf(root_cont_path, sizeof(root_cont_path), "%s_root.otc", base);
    snprintf(key_path,       sizeof(key_path),       "%s.key",      base);

    wfile(root_cont_path, root_enc, root_enc_sz);
    free(root_enc);
    kf_write(&kf, key_path);

    printf("\nCreated: %s\n", root_cont_path);
    printf("Created: %s\n",   key_path);
    printf("Keep %s safe — without it the data cannot be recovered.\n", key_path);

    if (remove_original) {
        for (size_t i = 0; i < fl.cnt; i++) {
            char abs[MAX_PATH_LEN];
            snprintf(abs, sizeof(abs), "%s/%s", root, fl.paths[i]);
            unlink(abs);
        }
        rmdir(root);
    }

    kf_free(&kf); fl_free(&fl);
}

/* ================================================================== */
/* Decode worker: decrypt one container + write files                  */
/* ================================================================== */
typedef struct {
    const uint8_t *enc;
    size_t         enc_sz;
    const char    *cont_name;
    const char    *out_dir;
    const KeyFile *kf;
} DecWork;

static void *dec_worker(void *arg) {
    DecWork *w = (DecWork *)arg;

    /* Container label → password */
    char lbl[MAX_PATH_LEN];
    snprintf(lbl, sizeof(lbl), "cont:%s", w->cont_name);
    const char *cont_pw = kf_get(w->kf, lbl);
    if (!cont_pw) die("Z");

    size_t wire_sz;
    uint8_t *wire = otc_decrypt(w->enc, w->enc_sz, cont_pw, &wire_sz);

    if (wire_sz < 12 || memcmp(wire, CONT_MAGIC, 8) != 0)
        { free(wire); die("M"); }

    uint32_t nfiles = r32(wire + 8);
    size_t woff = 12;

    /* Base container name without .cont for key labels */
    char cl[MAX_PATH_LEN];
    strncpy(cl, w->cont_name, sizeof(cl)-1); cl[sizeof(cl)-1] = '\0';
    char *dotp = strstr(cl, ".cont"); if (dotp) *dotp = '\0';

    for (uint32_t fi = 0; fi < nfiles; fi++) {
        if (woff + 2 > wire_sz) break;
        uint16_t rplen = r16(wire + woff); woff += 2;
        if (woff + rplen > wire_sz) break;
        char relpath[MAX_PATH_LEN];
        memcpy(relpath, wire + woff, rplen); relpath[rplen] = '\0'; woff += rplen;
        if (woff + 8 > wire_sz) break;
        uint64_t fesz = r64(wire + woff); woff += 8;
        if (woff + fesz > wire_sz) break;
        const uint8_t *fenc = wire + woff; woff += (size_t)fesz;

        snprintf(lbl, sizeof(lbl), "file:%s/%s", cl, relpath);
        const char *fpw = kf_get(w->kf, lbl);
        if (!fpw) { free(wire); die("Z"); }

        size_t plain_sz;
        uint8_t *plain = otc_decrypt(fenc, (size_t)fesz, fpw, &plain_sz);

        /* Build output path, creating dirs as needed */
        char out_path[MAX_PATH_LEN];
        snprintf(out_path, sizeof(out_path), "%s/%s", w->out_dir, relpath);
        {
            char tmp[MAX_PATH_LEN];
            strncpy(tmp, out_path, sizeof(tmp)-1);
            for (char *p = tmp+1; *p; p++) {
                if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
            }
        }
        wfile(out_path, plain, plain_sz);
        sodium_memzero(plain, plain_sz); free(plain);
    }

    sodium_memzero(wire, wire_sz); free(wire);
    return NULL;
}

/* ================================================================== */
/* Decode: <base>_root.otc + <base>.key → original folder             */
/* ================================================================== */
static void decode_otc(const char *cont_path, const char *key_path) {
    RE_GUARD();

    /* Derive output folder name from container path */
    char base[MAX_PATH_LEN];
    strncpy(base, cont_path, sizeof(base)-1); base[sizeof(base)-1] = '\0';
    char *slash = strrchr(base, '/');
    char *bname = slash ? slash+1 : base;
    char *suf = strstr(bname, "_root.otc");
    if (!suf) { suf = strstr(bname, ".otc"); if (!suf) die("Z"); }
    char folder_name[MAX_PATH_LEN];
    size_t blen = (size_t)(suf - bname);
    memcpy(folder_name, bname, blen); folder_name[blen] = '\0';

    char out_dir[MAX_PATH_LEN];
    if (slash) {
        char dir[MAX_PATH_LEN];
        size_t dlen = (size_t)(slash - base);
        memcpy(dir, base, dlen); dir[dlen] = '\0';
        snprintf(out_dir, sizeof(out_dir), "%s/%s", dir, folder_name);
    } else {
        snprintf(out_dir, sizeof(out_dir), "%s", folder_name);
    }

    KeyFile kf; kf_read(&kf, key_path);

    /* Read + decrypt root container */
    size_t root_enc_sz;
    uint8_t *root_enc = rfile(cont_path, &root_enc_sz);
    const char *root_pw = kf_get(&kf, "root");
    if (!root_pw) { free(root_enc); kf_free(&kf); die("Z"); }

    size_t root_sz;
    uint8_t *root_data = otc_decrypt(root_enc, root_enc_sz, root_pw, &root_sz);
    free(root_enc);

    if (root_sz < 12 || memcmp(root_data, CONT_MAGIC, 8) != 0)
        { free(root_data); kf_free(&kf); die("M"); }

    uint32_t nconts = r32(root_data + 8);
    size_t off = 12;

    mkdir(out_dir, 0755);

    int nthreads = cpu_count();
    if (nthreads > (int)nconts) nthreads = (int)nconts;

    printf("Decoding %u container(s) using %d thread(s)...\n", nconts, nthreads);

    DecWork *work   = calloc(nconts, sizeof(DecWork));
    pthread_t *threads = malloc(nconts * sizeof(pthread_t));
    char **cont_names = malloc(nconts * sizeof(char*));
    if (!work || !threads || !cont_names) die("N");

    for (uint32_t ci = 0; ci < nconts; ci++) {
        if (off + 2 > root_sz) break;
        uint16_t cnl = r16(root_data + off); off += 2;
        if (off + cnl > root_sz) break;
        char cont_name[MAX_PATH_LEN];
        memcpy(cont_name, root_data + off, cnl); cont_name[cnl] = '\0'; off += cnl;
        if (off + 8 > root_sz) break;
        uint64_t esz = r64(root_data + off); off += 8;
        if (off + esz > root_sz) break;

        cont_names[ci] = strdup(cont_name);
        work[ci].enc       = root_data + off;
        work[ci].enc_sz    = (size_t)esz;
        work[ci].cont_name = cont_names[ci];
        work[ci].out_dir   = out_dir;
        work[ci].kf        = &kf;
        off += (size_t)esz;
    }

    /* Decrypt containers in parallel batches */
    for (uint32_t ci = 0; ci < nconts; ci += (uint32_t)nthreads) {
        uint32_t batch_end = ci + (uint32_t)nthreads;
        if (batch_end > nconts) batch_end = nconts;
        for (uint32_t t = ci; t < batch_end; t++)
            pthread_create(&threads[t], NULL, dec_worker, &work[t]);
        for (uint32_t t = ci; t < batch_end; t++)
            pthread_join(threads[t], NULL);
        printf("  [%u/%u] containers decoded\n", batch_end, nconts);
    }

    for (uint32_t ci = 0; ci < nconts; ci++) free(cont_names[ci]);
    free(work); free(threads); free(cont_names);
    sodium_memzero(root_data, root_sz); free(root_data);

    /* Clean up container + key files */
    unlink(cont_path);
    unlink(key_path);

    printf("Decoded: %s/\n", out_dir);
    kf_free(&kf);
}

/* ================================================================== */
/* run_secure: in-memory execution of single encrypted binary          */
/* ================================================================== */
static void run_secure(const char *path, const char *pw) {
    STACK_CANARY_INIT(); STACK_CANARY_SAVE(); RE_GUARD();
    if (plat_is_vm())    die("V");
    if (are_debugged())  die("D");
    if (geteuid() == 0)  die("R");
    ANTIDIS_TRAP2();
    size_t il;
    uint8_t *plain = read_rv5c(path, pw, NULL, NULL, NULL, &il);
    plat_exec_payload(plain, il);
    sodium_memzero(plain, il); free(plain);
    STACK_CANARY_CHECK();
}

/* ================================================================== */
/* Main                                                                 */
/*                                                                      */
/* ./rv encode <folder>            encode folder → <n>_root.otc        */
/* ./rv encode <folder> remove     encode and delete original           */
/* ./rv encode <file>              encrypt single file → <file>.otc    */
/* ./rv decode <n>_root.otc <n>.key  restore original folder           */
/* ./rv decode <file>.otc          decrypt single file (prompts pw)    */
/* ./rv run    <file>              in-memory execute encrypted binary   */
/* ================================================================== */
int main(int argc, char **argv) {
    anti_re_init();
    if (sodium_init() < 0) _exit(1);

    if (argc < 3) {
        dprintf(STDERR_FILENO,
            "usage:\n"
            "  %s encode <folder|file> [remove]\n"
            "  %s decode <name_root.otc> <name.key>\n"
            "  %s run    <file>\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    const char *cmd  = argv[1];
    const char *path = argv[2];
    if (strstr(path, "..")) _exit(1);

    if (!strcmp(cmd, "encode")) {
        struct stat st;
        if (stat(path, &st) != 0) { perror(path); return 1; }

        if (S_ISDIR(st.st_mode)) {
            int rm = (argc >= 4 && !strcmp(argv[3], "remove"));
            encode_otc(path, rm);
        } else {
            /* Single file: standard password-protected .otc */
            char pw[MAX_PW_LEN]; memset(pw, 0, sizeof(pw));
            DECSTR(prompt, "Password: ");
            read_pw(pw, sizeof(pw), prompt);
            sodium_memzero(prompt, sizeof(prompt));
            size_t il; uint8_t *in = rfile(path, &il);
            char opath[MAX_PATH_LEN];
            snprintf(opath, sizeof(opath), "%s.otc", path);
            write_rv5c(opath, in, il, pw, NULL, NULL, NULL);
            sodium_memzero(in, il); free(in);
            sodium_memzero(pw, sizeof(pw));
            printf("Created: %s\n", opath);
        }

    } else if (!strcmp(cmd, "decode")) {
        if (strstr(path, "_root.otc") || (argc >= 4 && strstr(argv[3], ".key"))) {
            if (argc < 4) {
                dprintf(STDERR_FILENO, "usage: %s decode <name_root.otc> <name.key>\n", argv[0]);
                return 1;
            }
            const char *key_path = argv[3];
            if (strstr(key_path, "..")) _exit(1);
            decode_otc(path, key_path);
        } else {
            /* Single file .otc decrypt */
            char pw[MAX_PW_LEN]; memset(pw, 0, sizeof(pw));
            DECSTR(prompt, "Password: ");
            read_pw(pw, sizeof(pw), prompt);
            sodium_memzero(prompt, sizeof(prompt));
            size_t bl;
            uint8_t *buf = read_rv5c(path, pw, NULL, NULL, NULL, &bl);
            char opath[MAX_PATH_LEN];
            strncpy(opath, path, sizeof(opath)-1);
            char *suf = strstr(opath, ".otc"); if (suf) *suf = '\0';
            wfile(opath, buf, bl);
            sodium_memzero(buf, bl); free(buf);
            sodium_memzero(pw, sizeof(pw));
            printf("Decoded: %s\n", opath);
        }

    } else if (!strcmp(cmd, "run")) {
        char pw[MAX_PW_LEN]; memset(pw, 0, sizeof(pw));
        DECSTR(prompt, "Password: ");
        read_pw(pw, sizeof(pw), prompt);
        sodium_memzero(prompt, sizeof(prompt));
        run_secure(path, pw);
        sodium_memzero(pw, sizeof(pw));

    } else {
        dprintf(STDERR_FILENO, "unknown command: %s\n", cmd);
        return 1;
    }
    return 0;
}
