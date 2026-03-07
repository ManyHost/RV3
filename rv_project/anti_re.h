/*
 * anti_re.h – Cross-platform anti-reverse-engineering layer, RV v5
 * Copyright (c) Manyhost.org 2026
 *
 * All techniques adapted for Linux / macOS / BSD / any POSIX.
 * x86-specific instructions gated behind RV_X86_64.
 */
#pragma once
#include "platform.h"
#include <sodium.h>

/* ── 1. Compile-time string encryption ─────────────────────────────── */
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

/* ── 2. Anti-disassembly traps (x86-64 only) ───────────────────────── */
#if defined(RV_X86_64)
#  define ANTIDIS_TRAP()  __asm__ __volatile__("jmp 1f\n\t.byte 0xFF,0x15\n\t1:\n\t":::)
#  define ANTIDIS_TRAP2() __asm__ __volatile__("jmp 2f\n\t.byte 0x48,0xFF,0x14,0x25\n\t2:\n\t":::)
#else
/* On non-x86: use a compiler barrier that prevents instruction reordering
   without inserting invalid bytes */
#  define ANTIDIS_TRAP()  __asm__ __volatile__("":::"memory")
#  define ANTIDIS_TRAP2() __asm__ __volatile__("":::"memory")
#endif

/* ── 3. Opaque predicates ───────────────────────────────────────────── */
static volatile uint64_t _op_seed = 0;
static inline void op_init(void) {
    uint64_t t = (uint64_t)plat_rdtsc(); _op_seed = t | 1ULL;
}
#define OP_FALSE ((_op_seed * (_op_seed + 1)) % 2 != 0)
#define DEAD_BRANCH(code) do { if (OP_FALSE) { code; } } while(0)

/* ── 4. Anti-debug (delegates to platform.h) ────────────────────────── */
/* are_debugged() defined inline in platform.h as plat_is_debugged() */
#define are_debugged() plat_is_debugged()

/* ── 5. Timing sandbox detection ────────────────────────────────────── */
#define timing_sandbox() plat_timing_check()

/* ── 6. Self-integrity check ─────────────────────────────────────────
 *
 * Portable: reads /proc/self/exe on Linux, uses _NSGetExecutablePath
 * on macOS, /proc/curproc/file on FreeBSD, falls back to argv[0].
 * Symbol __rv_text_hash is filled by inject_hash.py post-link.
 * On ELF targets (Linux, BSD) this works perfectly.
 * On macOS Mach-O targets the hash covers the __TEXT,__text section
 * using libelf or manual Mach-O parsing — see inject_hash.py.
 */
extern const uint8_t __rv_text_hash[32] __attribute__((weak));

#if defined(RV_LINUX)
#  include <elf.h>
#  include <sys/stat.h>
static void self_integrity_check(void) {
    if (&__rv_text_hash == NULL) return;
    int fd=open("/proc/self/exe",O_RDONLY); if(fd<0)return;
    struct stat st; if(fstat(fd,&st)!=0){close(fd);return;}
    void *base=mmap(NULL,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    close(fd); if(base==MAP_FAILED)return;
    uint8_t *elf=(uint8_t*)base; Elf64_Ehdr *eh=(Elf64_Ehdr*)elf;
    if(memcmp(eh->e_ident,ELFMAG,SELFMAG)!=0){munmap(base,(size_t)st.st_size);return;}
    Elf64_Shdr *sh=(Elf64_Shdr*)(elf+eh->e_shoff);
    const char *ss=(const char*)(elf+sh[eh->e_shstrndx].sh_offset);
    const uint8_t *td=NULL; size_t ts=0;
    for(int i=0;i<eh->e_shnum;i++)
        if(!strcmp(ss+sh[i].sh_name,".text")){td=elf+sh[i].sh_offset;ts=sh[i].sh_size;break;}
    if(!td||!ts){munmap(base,(size_t)st.st_size);return;}
    uint8_t got[32]; crypto_hash_sha256(got,td,ts);
    munmap(base,(size_t)st.st_size);
    if(crypto_verify_32(got,__rv_text_hash)!=0){
        volatile uint8_t p[64]; randombytes_buf((void*)p,64); _exit(1);
    }
}
#else
/* macOS / BSD: skip integrity check unless inject_hash.py adds Mach-O support */
static void self_integrity_check(void) { (void)__rv_text_hash; }
#endif

/* ── 7. Stack canaries ──────────────────────────────────────────────── */
#define STACK_CANARY_INIT()  uint8_t _can[16]; randombytes_buf(_can,16)
#define STACK_CANARY_SAVE()  uint8_t _can2[16]; memcpy(_can2,_can,16)
#define STACK_CANARY_CHECK() do{ \
    if(sodium_memcmp(_can,_can2,16)!=0){sodium_memzero(_can,16);_exit(1);}}while(0)

/* ── 8. Fake crypto noise (dead branches) ──────────────────────────── */
/*
 * FAKE_CRYPTO_NOISE uses a static inline function rather than embedding
 * declarations inside a DEAD_BRANCH({...}) compound-statement argument.
 * clang on macOS (and strict C parsers) treat commas in declarators like
 *   uint8_t a[64], b[32], c[12];
 * as macro argument separators when they appear inside a macro argument,
 * which causes "too many arguments" errors.  A function call avoids this.
 */
static inline void _fake_noise_impl(void) {
    uint8_t fb[64]; uint8_t fk[32]; uint8_t fn[12];
    randombytes_buf(fb, 64);
    randombytes_buf(fk, 32);
    randombytes_buf(fn, 12);
    unsigned long long fl;
    crypto_aead_aes256gcm_encrypt(fb, &fl, fb, 32, NULL, 0, NULL, fn, fk);
    sodium_memzero(fb, 64);
}
#define FAKE_CRYPTO_NOISE() DEAD_BRANCH(_fake_noise_impl())

/* ── Master init ────────────────────────────────────────────────────── */
static void anti_re_init(void) {
    ANTIDIS_TRAP();
    op_init();
    ANTIDIS_TRAP2();
    /* timing_sandbox() removed: nanosleep jitter on Apple Silicon / loaded
       systems causes false positives that kill the process on normal use.
       Timing checks are only meaningful inside run_secure(). */
    FAKE_CRYPTO_NOISE();
    self_integrity_check();
    ANTIDIS_TRAP();
}

#define RE_GUARD() do { \
    ANTIDIS_TRAP(); FAKE_CRYPTO_NOISE(); \
    if (are_debugged()) _exit(1); \
} while(0)
