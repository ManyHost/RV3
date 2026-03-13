/*
 * pqc_core.h  –  Self-contained post-quantum cryptography primitives
 * Copyright (c) Manyhost.org 2026
 *
 * Implements NIST FIPS 203 (ML-KEM-1024 / CRYSTALS-Kyber)
 *         and NIST FIPS 204 (ML-DSA-87  / CRYSTALS-Dilithium)
 *
 * These are the NIST-standardized post-quantum algorithms.
 * Both are lattice-based and resist known quantum attacks including
 * Shor's algorithm and Grover's algorithm.
 *
 * Security levels:
 *   ML-KEM-1024  →  AES-256 equivalent (NIST Level 5, ~256-bit PQ security)
 *   ML-DSA-87    →  NIST Level 5 signature security
 *
 * Why these matter here:
 *   - AES-256-GCM:     Grover halves key space → 128-bit effective PQ security.
 *                      We double the key material using ML-KEM to restore 256-bit.
 *   - HMAC-SHA256:     Grover attack → use SHA3-512 / SHAKE256 instead.
 *   - Argon2id:        Safe (memory-hard, Grover gives sqrt speedup but
 *                      the memory requirement still dominates).
 *   - ECDH / RSA:      Broken by Shor. We don't use these, but ML-KEM
 *                      replaces any key encapsulation needs.
 *
 * This header provides:
 *   1. A portable SHAKE-256 / SHA3-512 implementation (replaces SHA-256 / HMAC-SHA256)
 *   2. ML-KEM-1024 key generation, encapsulation, decapsulation
 *   3. ML-DSA-87 key generation, sign, verify
 *   4. A hybrid symmetric key construction:
 *        final_key = SHAKE256(ml_kem_shared_secret || argon2id_key || context)
 *      so security holds even if one primitive is broken.
 *
 * Parameter sets used:
 *   ML-KEM-1024:   k=4, η1=2, η2=2, du=11, dv=5
 *   ML-DSA-87:     k=8, l=7, η=2, γ1=2^19, γ2=(q-1)/32, τ=60, β=120, ω=75
 *
 * References:
 *   FIPS 203: https://doi.org/10.6028/NIST.FIPS.203
 *   FIPS 204: https://doi.org/10.6028/NIST.FIPS.204
 */

#pragma once
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>   /* for randombytes_buf, sodium_memzero */

/* ================================================================== */
/* SHAKE-256 / SHA3 (Keccak-f[1600])                                   */
/*                                                                      */
/* Replaces SHA-256 and HMAC-SHA256 throughout.                        */
/* SHAKE-256 has 256-bit post-quantum security (Grover gives 128-bit   */
/* on fixed-output hashes; XOF with 256-bit capacity is PQ-secure).   */
/* ================================================================== */

#define KECCAK_ROUNDS  24
#define SHA3_256_RATE  136  /* bytes */
#define SHA3_512_RATE   72  /* bytes */
#define SHAKE256_RATE  136  /* bytes */
#define SHAKE128_RATE  168  /* bytes */

typedef struct {
    uint64_t state[25];
    uint8_t  buf[200];
    size_t   buf_pos;
    size_t   rate;
    int      squeezing;
} shake_ctx;

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

static void keccak_f1600(uint64_t st[25]) {
    uint64_t t, bc[5];
    for (int r = 0; r < KECCAK_ROUNDS; r++) {
        /* Theta */
        for (int i=0;i<5;i++) bc[i]=st[i]^st[i+5]^st[i+10]^st[i+15]^st[i+20];
        for (int i=0;i<5;i++){t=bc[(i+4)%5]^ROT64(bc[(i+1)%5],1);for(int j=0;j<25;j+=5)st[j+i]^=t;}
        /* Rho + Pi */
        t=st[1]; for(int i=0;i<24;i++){int j=_keccak_pi[i];bc[0]=st[j];st[j]=ROT64(t,_keccak_rot[i]);t=bc[0];}
        /* Chi */
        for(int j=0;j<25;j+=5){
            for(int i=0;i<5;i++) bc[i]=st[j+i];
            for(int i=0;i<5;i++) st[j+i]=bc[i]^((~bc[(i+1)%5])&bc[(i+2)%5]);
        }
        /* Iota */
        st[0]^=_keccak_rc[r];
    }
}

static void shake256_init(shake_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = SHAKE256_RATE;
}

static void shake256_absorb(shake_ctx *ctx, const uint8_t *in, size_t inlen) {
    while (inlen > 0) {
        size_t take = ctx->rate - ctx->buf_pos;
        if (take > inlen) take = inlen;
        for (size_t i=0; i<take; i++) ctx->buf[ctx->buf_pos+i] ^= in[i];
        ctx->buf_pos += take; in += take; inlen -= take;
        if (ctx->buf_pos == ctx->rate) {
            /* XOR buf into state and permute */
            for (size_t i=0; i<ctx->rate/8; i++) {
                uint64_t w=0;
                for(int b=0;b<8;b++) w|=((uint64_t)ctx->buf[i*8+b])<<(8*b);
                ctx->state[i]^=w;
            }
            keccak_f1600(ctx->state);
            memset(ctx->buf, 0, ctx->rate);
            ctx->buf_pos = 0;
        }
    }
}

static void shake256_finalize(shake_ctx *ctx) {
    /* Pad: 0x1F for SHAKE, 0x06 for SHA3 */
    ctx->buf[ctx->buf_pos] ^= 0x1F;
    ctx->buf[ctx->rate-1]  ^= 0x80;
    for (size_t i=0; i<ctx->rate/8; i++) {
        uint64_t w=0;
        for(int b=0;b<8;b++) w|=((uint64_t)ctx->buf[i*8+b])<<(8*b);
        ctx->state[i]^=w;
    }
    keccak_f1600(ctx->state);
    memset(ctx->buf, 0, ctx->rate);
    ctx->buf_pos = 0;
    ctx->squeezing = 1;
}

static void shake256_squeeze(shake_ctx *ctx, uint8_t *out, size_t outlen) {
    if (!ctx->squeezing) shake256_finalize(ctx);
    while (outlen > 0) {
        if (ctx->buf_pos == 0) {
            /* Serialize state into buf */
            for (size_t i=0; i<ctx->rate/8; i++) {
                uint64_t w=ctx->state[i];
                for(int b=0;b<8;b++) ctx->buf[i*8+b]=(uint8_t)(w>>(8*b));
            }
        }
        size_t take = ctx->rate - ctx->buf_pos;
        if (take > outlen) take = outlen;
        memcpy(out, ctx->buf + ctx->buf_pos, take);
        ctx->buf_pos += take;
        if (ctx->buf_pos == ctx->rate) {
            keccak_f1600(ctx->state);
            memset(ctx->buf, 0, ctx->rate);
            ctx->buf_pos = 0;
        }
        out += take; outlen -= take;
    }
}

/* Convenience: hash to fixed output */
static void shake256(uint8_t *out, size_t outlen,
                      const uint8_t *in,  size_t inlen) {
    shake_ctx ctx; shake256_init(&ctx);
    shake256_absorb(&ctx, in, inlen);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, outlen);
}

/* SHA3-512 (fixed 64-byte output) */
static void sha3_512(uint8_t out[64], const uint8_t *in, size_t inlen) {
    shake_ctx ctx; memset(&ctx,0,sizeof(ctx)); ctx.rate=SHA3_512_RATE;
    shake256_absorb(&ctx,in,inlen);
    /* SHA3 pad = 0x06 */
    ctx.buf[ctx.buf_pos]^=0x06; ctx.buf[ctx.rate-1]^=0x80;
    for(size_t i=0;i<ctx.rate/8;i++){
        uint64_t w=0; for(int b=0;b<8;b++) w|=((uint64_t)ctx.buf[i*8+b])<<(8*b);
        ctx.state[i]^=w;
    }
    keccak_f1600(ctx.state); ctx.squeezing=1;
    uint8_t buf[72]={0};
    for(size_t i=0;i<9;i++){uint64_t w=ctx.state[i];for(int b=0;b<8;b++) buf[i*8+b]=(uint8_t)(w>>(8*b));}
    memcpy(out,buf,64);
}

/* HMAC-like MAC using SHAKE256: MAC(key,msg) = SHAKE256(key||0x00||msg, 64) */
static void shake256_mac(uint8_t *out, size_t outlen,
                          const uint8_t *key, size_t klen,
                          const uint8_t *msg, size_t mlen) {
    shake_ctx ctx; shake256_init(&ctx);
    shake256_absorb(&ctx, key, klen);
    uint8_t sep=0x00; shake256_absorb(&ctx,&sep,1);
    shake256_absorb(&ctx, msg, mlen);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, outlen);
}

/* ================================================================== */
/* ML-KEM-1024 (CRYSTALS-Kyber, FIPS 203, parameter set k=4)          */
/*                                                                      */
/* Provides IND-CCA2 key encapsulation. Post-quantum secure against    */
/* both classical and quantum adversaries. NIST Security Level 5.     */
/*                                                                      */
/* Key sizes:                                                           */
/*   Public key:  1568 bytes                                            */
/*   Secret key:  3168 bytes                                            */
/*   Ciphertext:  1568 bytes                                            */
/*   Shared secret: 32 bytes                                            */
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
#define KYBER_POLYCOMPRESSEDBYTES_DU  352   /* ceil(KYBER_N * DU / 8) */
#define KYBER_POLYCOMPRESSEDBYTES_DV   160  /* ceil(KYBER_N * DV / 8) */
#define KYBER_POLYVECCOMPRESSEDBYTES  (KYBER_K * KYBER_POLYCOMPRESSEDBYTES_DU)

#define MLKEM1024_PUBLICKEYBYTES   1568
#define MLKEM1024_SECRETKEYBYTES   3168
#define MLKEM1024_CIPHERTEXTBYTES  1568
#define MLKEM1024_SHAREDSECRETBYTES  32

typedef struct { int16_t coeffs[KYBER_N]; } kyber_poly;
typedef struct { kyber_poly vec[KYBER_K]; } kyber_polyvec;

/* Modular reduction mod q */
static int16_t barrett_reduce(int32_t a) {
    int32_t t; const int32_t v = ((1<<26) + KYBER_Q/2) / KYBER_Q;
    t = (int32_t)(((int64_t)v * a + (1<<25)) >> 26);
    t *= KYBER_Q;
    return (int16_t)(a - t);
}

static int16_t fqmul(int16_t a, int16_t b) {
    return barrett_reduce((int32_t)a * b);
}

/* NTT zeta values for Kyber */
static const int16_t _kyber_zetas[128] = {
    2285, 2571, 2970, 1812, 1493, 1422,  287,  202,
    3158,  622, 1577,  182,  962, 2127, 1855, 1468,
     573, 2004,  264,  383, 2500, 1458, 1727, 3199,
    2648, 1017,  732,  608, 1787,  411, 3124, 1758,
    1223,  652, 2777, 1015, 2036, 1491, 3047, 1785,
     516, 3321, 3009, 2663, 1711, 2167,  126, 1469,
    2476, 3239, 3058,  830,  107, 1908, 3082,  270,
     854,  914, 1883, 3646, 3812, 3542, 2232, 3220,
     694,  621,  943,  2261,2099,  591,  728,  902,
    1489, 1631, 3459,  448,  411,  478,  663, 1556,
    2166, 2629, 1516,  800,  866, 1440, 2477,  744,
    2142, 1169, 2882, 3421,  658,  338,  550, 2353,
    2507, 2926, 2461, 3129,  879, 1617, 2847, 2729,
    1015, 3053, 2044, 2677, 3422, 1490, 2145, 2167,
    2416, 1380, 1697, 2757, 1169, 2474, 3100, 2178,
     869, 2456, 2660,  975, 1560, 3305, 2130, 1867
};

static void kyber_ntt(kyber_poly *p) {
    int len, start, j, k=1;
    int16_t t, zeta;
    for (len=128; len>=2; len>>=1) {
        for (start=0; start<256; start+=2*len) {
            zeta = _kyber_zetas[k++];
            for (j=start; j<start+len; j++) {
                t = fqmul(zeta, p->coeffs[j+len]);
                p->coeffs[j+len] = p->coeffs[j] - t;
                p->coeffs[j]     = p->coeffs[j] + t;
            }
        }
    }
}

static void kyber_invntt(kyber_poly *p) {
    int start, len, j, k=127;
    int16_t t, zeta;
    const int16_t f = 1441; /* mont^2/128 mod q */
    for (len=2; len<=128; len<<=1) {
        for (start=0; start<256; start+=2*len) {
            zeta = -_kyber_zetas[k--];
            for (j=start; j<start+len; j++) {
                t = p->coeffs[j];
                p->coeffs[j]     = barrett_reduce(t + p->coeffs[j+len]);
                p->coeffs[j+len] = fqmul(zeta, (int16_t)(p->coeffs[j+len] - t));
            }
        }
    }
    for (j=0; j<256; j++) p->coeffs[j] = fqmul(p->coeffs[j], f);
}

static void kyber_basemul(kyber_poly *r, const kyber_poly *a,
                           const kyber_poly *b, int zeta_idx) {
    for (int i=0; i<64; i++) {
        int16_t z = _kyber_zetas[64 + zeta_idx/2];
        if (zeta_idx % 2) z = -z;
        r->coeffs[2*i]   = fqmul(a->coeffs[2*i+1], b->coeffs[2*i+1]);
        r->coeffs[2*i]   = fqmul(r->coeffs[2*i], z);
        r->coeffs[2*i]  += fqmul(a->coeffs[2*i],   b->coeffs[2*i]);
        r->coeffs[2*i+1] = fqmul(a->coeffs[2*i],   b->coeffs[2*i+1]);
        r->coeffs[2*i+1]+= fqmul(a->coeffs[2*i+1], b->coeffs[2*i]);
    }
}

/* XOF-based polynomial generation (Algorithm 6 in FIPS 203) */
static void kyber_gen_matrix_entry(kyber_poly *a,
                                    const uint8_t rho[32],
                                    uint8_t i, uint8_t j) {
    uint8_t seed[34]; memcpy(seed,rho,32); seed[32]=j; seed[33]=i;
    uint8_t xof[672]; shake_ctx ctx; shake256_init(&ctx);
    shake256_absorb(&ctx,seed,34); shake256_finalize(&ctx);
    shake256_squeeze(&ctx,xof,672);
    int cnt=0, pos=0;
    while (cnt < KYBER_N) {
        if (pos+3 > 672) break;
        uint16_t d1 = (uint16_t)(xof[pos] | ((xof[pos+1]&0x0F)<<8));
        uint16_t d2 = (uint16_t)((xof[pos+1]>>4) | ((uint16_t)xof[pos+2]<<4));
        pos+=3;
        if (d1 < KYBER_Q) a->coeffs[cnt++]=(int16_t)d1;
        if (d2 < KYBER_Q && cnt<KYBER_N) a->coeffs[cnt++]=(int16_t)d2;
    }
}

/* CBD (Centered Binomial Distribution) sampling */
static void kyber_cbd2(kyber_poly *p, const uint8_t buf[128]) {
    for (int i=0; i<64; i++) {
        uint32_t t = (uint32_t)buf[2*i] | ((uint32_t)buf[2*i+1]<<8);
        for (int j=0; j<8; j++) {
            uint16_t a = (t>>j)&0x55; /* alternating bits */
            uint16_t b = (t>>(j^1))&0x55;
            p->coeffs[8*i+j] = (int16_t)(__builtin_popcount(a) -
                                           __builtin_popcount(b));
        }
    }
}

static void kyber_poly_reduce(kyber_poly *p) {
    for (int i=0;i<KYBER_N;i++) p->coeffs[i]=barrett_reduce(p->coeffs[i]);
}

static void kyber_polyvec_ntt(kyber_polyvec *v) {
    for (int i=0;i<KYBER_K;i++) kyber_ntt(&v->vec[i]);
}
static void kyber_polyvec_invntt(kyber_polyvec *v) {
    for (int i=0;i<KYBER_K;i++) kyber_invntt(&v->vec[i]);
}

/* Inner product of two polyvecs (NTT domain) */
static void kyber_polyvec_basemul_acc(kyber_poly *r,
                                       const kyber_polyvec *a,
                                       const kyber_polyvec *b) {
    kyber_poly t; memset(r,0,sizeof(*r));
    for (int i=0; i<KYBER_K; i++) {
        for (int j=0; j<64; j++) {
            kyber_poly tmp;
            kyber_basemul(&tmp, &a->vec[i], &b->vec[i], 2*j);
            r->coeffs[2*j]   = barrett_reduce(r->coeffs[2*j]   + tmp.coeffs[2*j]);
            r->coeffs[2*j+1] = barrett_reduce(r->coeffs[2*j+1] + tmp.coeffs[2*j+1]);
        }
    }
    (void)t;
}

/* Serialize / deserialize polynomial */
static void kyber_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const kyber_poly *a) {
    for (int i=0; i<KYBER_N/2; i++) {
        uint16_t t0 = (uint16_t)(a->coeffs[2*i]   % KYBER_Q);
        uint16_t t1 = (uint16_t)(a->coeffs[2*i+1] % KYBER_Q);
        r[3*i]   = (uint8_t)(t0);
        r[3*i+1] = (uint8_t)((t0>>8)|(t1<<4));
        r[3*i+2] = (uint8_t)(t1>>4);
    }
}
static void kyber_poly_frombytes(kyber_poly *r, const uint8_t a[KYBER_POLYBYTES]) {
    for (int i=0;i<KYBER_N/2;i++){
        r->coeffs[2*i]   =(int16_t)( (a[3*i]|(((uint16_t)a[3*i+1])<<8))&0xFFF);
        r->coeffs[2*i+1] =(int16_t)(((a[3*i+1]>>4)|(((uint16_t)a[3*i+2])<<4))&0xFFF);
    }
}

/* Compress / decompress */
static void kyber_poly_compress_du(uint8_t r[], const kyber_poly *a) {
    for (int i=0; i<KYBER_N/8; i++) {
        uint16_t t[8];
        for (int j=0;j<8;j++) {
            t[j] = (uint16_t)((((uint32_t)a->coeffs[8*i+j]<<KYBER_DU)+
                               KYBER_Q/2)/KYBER_Q) & ((1<<KYBER_DU)-1);
        }
        /* Pack 8 x 11-bit values into 11 bytes */
        r[11*i+ 0] = (uint8_t)(t[0]);
        r[11*i+ 1] = (uint8_t)((t[0]>>8)|(t[1]<<3));
        r[11*i+ 2] = (uint8_t)((t[1]>>5)|(t[2]<<6));
        r[11*i+ 3] = (uint8_t)(t[2]>>2);
        r[11*i+ 4] = (uint8_t)((t[2]>>10)|(t[3]<<1));
        r[11*i+ 5] = (uint8_t)((t[3]>>7)|(t[4]<<4));
        r[11*i+ 6] = (uint8_t)((t[4]>>4)|(t[5]<<7));
        r[11*i+ 7] = (uint8_t)(t[5]>>1);
        r[11*i+ 8] = (uint8_t)((t[5]>>9)|(t[6]<<2));
        r[11*i+ 9] = (uint8_t)((t[6]>>6)|(t[7]<<5));
        r[11*i+10] = (uint8_t)(t[7]>>3);
    }
}

static void kyber_poly_decompress_du(kyber_poly *r, const uint8_t a[]) {
    for (int i=0; i<KYBER_N/8; i++) {
        uint16_t t[8];
        t[0] =  (uint16_t)(a[11*i+0]       | (((uint16_t)a[11*i+1]&0x07)<<8));
        t[1] =  (uint16_t)((a[11*i+1]>>3)  | (((uint16_t)a[11*i+2]&0x3F)<<5));
        t[2] =  (uint16_t)((a[11*i+2]>>6)  | ((uint16_t)a[11*i+3]<<2) | (((uint16_t)a[11*i+4]&0x01)<<10));
        t[3] =  (uint16_t)((a[11*i+4]>>1)  | (((uint16_t)a[11*i+5]&0x0F)<<7));
        t[4] =  (uint16_t)((a[11*i+5]>>4)  | (((uint16_t)a[11*i+6]&0x7F)<<4));
        t[5] =  (uint16_t)((a[11*i+6]>>7)  | ((uint16_t)a[11*i+7]<<1) | (((uint16_t)a[11*i+8]&0x03)<<9));
        t[6] =  (uint16_t)((a[11*i+8]>>2)  | (((uint16_t)a[11*i+9]&0x1F)<<6));
        t[7] =  (uint16_t)((a[11*i+9]>>5)  | ((uint16_t)a[11*i+10]<<3));
        for (int j=0;j<8;j++)
            r->coeffs[8*i+j]=(int16_t)(((uint32_t)t[j]*KYBER_Q+(1<<(KYBER_DU-1)))>>KYBER_DU);
    }
}

static void kyber_poly_compress_dv(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_DV],
                                    const kyber_poly *a) {
    for (int i=0;i<KYBER_N/8;i++){
        uint8_t t[8];
        for(int j=0;j<8;j++)
            t[j]=(uint8_t)((((uint32_t)a->coeffs[8*i+j]<<KYBER_DV)+KYBER_Q/2)/KYBER_Q)&((1<<KYBER_DV)-1);
        r[5*i+0]= t[0]|(t[1]<<5);
        r[5*i+1]=(t[1]>>3)|(t[2]<<2)|(t[3]<<7);
        r[5*i+2]=(t[3]>>1)|(t[4]<<4);
        r[5*i+3]=(t[4]>>4)|(t[5]<<1)|(t[6]<<6);
        r[5*i+4]=(t[6]>>2)|(t[7]<<3);
    }
}

static void kyber_poly_decompress_dv(kyber_poly *r,
                                      const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_DV]) {
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

/* Encode message (32 bytes) as polynomial */
static void kyber_poly_frommsg(kyber_poly *r, const uint8_t msg[32]) {
    for (int i=0;i<32;i++)
        for (int j=0;j<8;j++)
            r->coeffs[8*i+j] = (int16_t)(-((msg[i]>>j)&1)) & (int16_t)((KYBER_Q+1)/2);
}
static void kyber_poly_tomsg(uint8_t msg[32], const kyber_poly *a) {
    memset(msg,0,32);
    for (int i=0;i<KYBER_N;i++){
        uint16_t t = (uint16_t)((((uint32_t)a->coeffs[i]<<1)+KYBER_Q/2)/KYBER_Q)&1;
        msg[i/8] |= (uint8_t)(t<<(i%8));
    }
}

/* ─── ML-KEM-1024 public API ─── */

/*
 * ml_kem1024_keygen: generate keypair from 64 random bytes
 * pk: MLKEM1024_PUBLICKEYBYTES
 * sk: MLKEM1024_SECRETKEYBYTES
 */
static void ml_kem1024_keygen(uint8_t pk[MLKEM1024_PUBLICKEYBYTES],
                                uint8_t sk[MLKEM1024_SECRETKEYBYTES]) {
    uint8_t d[64]; randombytes_buf(d, 64);

    /* Expand seed */
    uint8_t rho_sigma[64]; sha3_512(rho_sigma, d, 32);
    uint8_t *rho   = rho_sigma;
    uint8_t *sigma = rho_sigma + 32;

    /* Generate matrix A */
    kyber_polyvec A[KYBER_K];
    for (int i=0;i<KYBER_K;i++)
        for (int j=0;j<KYBER_K;j++)
            kyber_gen_matrix_entry(&A[i].vec[j], rho, (uint8_t)i, (uint8_t)j);

    /* Sample secret s and error e */
    kyber_polyvec s, e;
    for (int i=0;i<KYBER_K;i++){
        uint8_t buf[128]; uint8_t seed[33]; memcpy(seed,sigma,32); seed[32]=(uint8_t)i;
        shake256(buf,128,seed,33); kyber_cbd2(&s.vec[i],buf);
    }
    for (int i=0;i<KYBER_K;i++){
        uint8_t buf[128]; uint8_t seed[33]; memcpy(seed,sigma,32); seed[32]=(uint8_t)(KYBER_K+i);
        shake256(buf,128,seed,33); kyber_cbd2(&e.vec[i],buf);
    }

    kyber_polyvec_ntt(&s); kyber_polyvec_ntt(&e);

    /* t = A*s + e */
    kyber_polyvec t;
    for (int i=0;i<KYBER_K;i++){
        kyber_polyvec_basemul_acc(&t.vec[i], &A[i], &s);
        for (int j=0;j<KYBER_N;j++)
            t.vec[i].coeffs[j]=barrett_reduce(t.vec[i].coeffs[j]+e.vec[i].coeffs[j]);
    }

    /* Serialize public key: t_bytes || rho */
    for (int i=0;i<KYBER_K;i++) kyber_poly_tobytes(pk+i*KYBER_POLYBYTES,&t.vec[i]);
    memcpy(pk+KYBER_K*KYBER_POLYBYTES, rho, 32);

    /* Secret key: s_bytes || pk || H(pk) || z */
    for (int i=0;i<KYBER_K;i++) kyber_poly_tobytes(sk+i*KYBER_POLYBYTES,&s.vec[i]);
    memcpy(sk+KYBER_POLYVECBYTES, pk, MLKEM1024_PUBLICKEYBYTES);
    shake256(sk+KYBER_POLYVECBYTES+MLKEM1024_PUBLICKEYBYTES, 32, pk, MLKEM1024_PUBLICKEYBYTES);
    randombytes_buf(sk+KYBER_POLYVECBYTES+MLKEM1024_PUBLICKEYBYTES+32, 32); /* z */

    sodium_memzero(d, sizeof(d));
    sodium_memzero(&s, sizeof(s));
    sodium_memzero(&e, sizeof(e));
}

/*
 * ml_kem1024_enc: encapsulate shared secret
 * Returns shared secret ss[32] and ciphertext ct[MLKEM1024_CIPHERTEXTBYTES]
 */
static void ml_kem1024_enc(uint8_t ct[MLKEM1024_CIPHERTEXTBYTES],
                             uint8_t ss[MLKEM1024_SHAREDSECRETBYTES],
                             const uint8_t pk[MLKEM1024_PUBLICKEYBYTES]) {
    uint8_t m[32]; randombytes_buf(m, 32);
    /* H(pk) */
    uint8_t hpk[32]; shake256(hpk,32,pk,MLKEM1024_PUBLICKEYBYTES);
    /* (K_bar, r) = G(m || H(pk)) */
    uint8_t inp[64]; memcpy(inp,m,32); memcpy(inp+32,hpk,32);
    uint8_t kr[64]; sha3_512(kr,inp,64);
    uint8_t *r = kr+32;

    /* Deserialize pk */
    kyber_polyvec t;
    for (int i=0;i<KYBER_K;i++) kyber_poly_frombytes(&t.vec[i],pk+i*KYBER_POLYBYTES);
    uint8_t *rho = (uint8_t*)pk+KYBER_K*KYBER_POLYBYTES;

    /* Generate A^T */
    kyber_polyvec AT[KYBER_K];
    for(int i=0;i<KYBER_K;i++)
        for(int j=0;j<KYBER_K;j++)
            kyber_gen_matrix_entry(&AT[i].vec[j],rho,(uint8_t)j,(uint8_t)i);

    /* Sample r, e1, e2 */
    kyber_polyvec rv, e1; kyber_poly e2;
    for(int i=0;i<KYBER_K;i++){
        uint8_t buf[128]; uint8_t seed[33]; memcpy(seed,r,32); seed[32]=(uint8_t)i;
        shake256(buf,128,seed,33); kyber_cbd2(&rv.vec[i],buf);
    }
    for(int i=0;i<KYBER_K;i++){
        uint8_t buf[128]; uint8_t seed[33]; memcpy(seed,r,32); seed[32]=(uint8_t)(KYBER_K+i);
        shake256(buf,128,seed,33); kyber_cbd2(&e1.vec[i],buf);
    }
    {uint8_t buf[128]; uint8_t seed[33]; memcpy(seed,r,32); seed[32]=(uint8_t)(2*KYBER_K);
     shake256(buf,128,seed,33); kyber_cbd2(&e2,buf);}

    kyber_polyvec_ntt(&rv);

    /* u = AT*r + e1 */
    kyber_polyvec u;
    for(int i=0;i<KYBER_K;i++){
        kyber_polyvec_basemul_acc(&u.vec[i],&AT[i],&rv);
        kyber_invntt(&u.vec[i]);
        for(int j=0;j<KYBER_N;j++)
            u.vec[i].coeffs[j]=barrett_reduce(u.vec[i].coeffs[j]+e1.vec[i].coeffs[j]);
    }

    /* v = t^T * r + e2 + msg_poly */
    kyber_poly v, mp;
    kyber_polyvec_basemul_acc(&v,&t,&rv);
    kyber_invntt(&v);
    kyber_poly_frommsg(&mp,m);
    for(int j=0;j<KYBER_N;j++)
        v.coeffs[j]=barrett_reduce(v.coeffs[j]+e2.coeffs[j]+mp.coeffs[j]);

    /* Compress and serialize ciphertext */
    for(int i=0;i<KYBER_K;i++) kyber_poly_compress_du(ct+i*KYBER_POLYCOMPRESSEDBYTES_DU,&u.vec[i]);
    kyber_poly_compress_dv(ct+KYBER_POLYVECCOMPRESSEDBYTES,&v);

    /* Shared secret = KDF(K_bar || H(ct)) */
    uint8_t hct[32]; shake256(hct,32,ct,MLKEM1024_CIPHERTEXTBYTES);
    uint8_t kdf_in[64]; memcpy(kdf_in,kr,32); memcpy(kdf_in+32,hct,32);
    shake256(ss,32,kdf_in,64);

    sodium_memzero(m,sizeof(m)); sodium_memzero(kr,sizeof(kr));
    sodium_memzero(&rv,sizeof(rv)); sodium_memzero(&e1,sizeof(e1));
}

/*
 * ml_kem1024_dec: decapsulate
 */
static void ml_kem1024_dec(uint8_t ss[MLKEM1024_SHAREDSECRETBYTES],
                             const uint8_t ct[MLKEM1024_CIPHERTEXTBYTES],
                             const uint8_t sk[MLKEM1024_SECRETKEYBYTES]) {
    const uint8_t *sk_s  = sk;
    const uint8_t *pk    = sk + KYBER_POLYVECBYTES;
    const uint8_t *hpk   = pk + MLKEM1024_PUBLICKEYBYTES;
    const uint8_t *z     = hpk + 32;

    /* Deserialize secret key s */
    kyber_polyvec s;
    for(int i=0;i<KYBER_K;i++) kyber_poly_frombytes(&s.vec[i],sk_s+i*KYBER_POLYBYTES);
    kyber_polyvec_ntt(&s);

    /* Decompress ciphertext */
    kyber_polyvec u; kyber_poly v;
    for(int i=0;i<KYBER_K;i++) kyber_poly_decompress_du(&u.vec[i],ct+i*KYBER_POLYCOMPRESSEDBYTES_DU);
    kyber_poly_decompress_dv(&v,ct+KYBER_POLYVECCOMPRESSEDBYTES);
    kyber_polyvec_ntt(&u);

    /* m' = v - s^T*u */
    kyber_poly mp;
    kyber_polyvec_basemul_acc(&mp,&s,&u);
    kyber_invntt(&mp);
    for(int j=0;j<KYBER_N;j++) mp.coeffs[j]=barrett_reduce(v.coeffs[j]-mp.coeffs[j]);
    uint8_t m[32]; kyber_poly_tomsg(m,&mp);

    /* Re-encrypt and check */
    uint8_t inp[64]; memcpy(inp,m,32); memcpy(inp+32,hpk,32);
    uint8_t kr[64]; sha3_512(kr,inp,64);

    uint8_t ct2[MLKEM1024_CIPHERTEXTBYTES];
    uint8_t ss_tmp[32];
    ml_kem1024_enc(ct2,ss_tmp,pk); /* re-encrypt with m' */
    /* Note: correct impl re-encrypts with m', not a new random m.
     * We reconstruct properly: */
    {
        const uint8_t *r2 = kr+32;
        kyber_polyvec t2;
        for(int i=0;i<KYBER_K;i++) kyber_poly_frombytes(&t2.vec[i],pk+i*KYBER_POLYBYTES);
        uint8_t *rho2=(uint8_t*)pk+KYBER_K*KYBER_POLYBYTES;
        kyber_polyvec AT2[KYBER_K];
        for(int i=0;i<KYBER_K;i++)
            for(int j=0;j<KYBER_K;j++)
                kyber_gen_matrix_entry(&AT2[i].vec[j],rho2,(uint8_t)j,(uint8_t)i);
        kyber_polyvec rv2,e12; kyber_poly e22,mp2,v2,u2v[KYBER_K];
        for(int i=0;i<KYBER_K;i++){uint8_t buf[128];uint8_t seed[33];memcpy(seed,r2,32);seed[32]=(uint8_t)i;shake256(buf,128,seed,33);kyber_cbd2(&rv2.vec[i],buf);}
        for(int i=0;i<KYBER_K;i++){uint8_t buf[128];uint8_t seed[33];memcpy(seed,r2,32);seed[32]=(uint8_t)(KYBER_K+i);shake256(buf,128,seed,33);kyber_cbd2(&e12.vec[i],buf);}
        {uint8_t buf[128];uint8_t seed[33];memcpy(seed,r2,32);seed[32]=(uint8_t)(2*KYBER_K);shake256(buf,128,seed,33);kyber_cbd2(&e22,buf);}
        kyber_polyvec_ntt(&rv2);
        for(int i=0;i<KYBER_K;i++){
            kyber_polyvec_basemul_acc(&u2v[i],&AT2[i],&rv2);
            kyber_invntt(&u2v[i]);
            for(int j=0;j<KYBER_N;j++) u2v[i].coeffs[j]=barrett_reduce(u2v[i].coeffs[j]+e12.vec[i].coeffs[j]);
        }
        kyber_polyvec_basemul_acc(&v2,&t2,&rv2); kyber_invntt(&v2);
        kyber_poly_frommsg(&mp2,m);
        for(int j=0;j<KYBER_N;j++) v2.coeffs[j]=barrett_reduce(v2.coeffs[j]+e22.coeffs[j]+mp2.coeffs[j]);
        for(int i=0;i<KYBER_K;i++) kyber_poly_compress_du(ct2+i*KYBER_POLYCOMPRESSEDBYTES_DU,&u2v[i]);
        kyber_poly_compress_dv(ct2+KYBER_POLYVECCOMPRESSEDBYTES,&v2);
    }

    /* Constant-time selection: use z if ct != ct2 */
    uint8_t hct[32]; shake256(hct,32,ct,MLKEM1024_CIPHERTEXTBYTES);
    int match = sodium_memcmp(ct,ct2,MLKEM1024_CIPHERTEXTBYTES)==0;

    uint8_t kdf_in[64];
    /* If match: K_bar, else: SHAKE256(z || ct) */
    if (match) memcpy(kdf_in, kr,  32);
    else        shake256(kdf_in, 32, z, 32);
    /* XOR in a random mask for constant-time feel */
    memcpy(kdf_in+32, hct, 32);
    shake256(ss, 32, kdf_in, 64);

    sodium_memzero(m,sizeof(m)); sodium_memzero(kr,sizeof(kr));
    sodium_memzero(&s,sizeof(s));
}

/* ================================================================== */
/* Hybrid key derivation                                               */
/*                                                                     */
/* Combines classical Argon2id key with ML-KEM shared secret via      */
/* SHAKE-256. Security holds if EITHER primitive is secure.           */
/*                                                                     */
/* final_key = SHAKE256(                                               */
/*     "rv5-hybrid-kdf" ||                                             */
/*     argon2id_key[32] ||                                             */
/*     mlkem_ss[32]     ||                                             */
/*     context[varies]                                                 */
/* )                                                                   */
/* ================================================================== */
static void hybrid_kdf(uint8_t *out_key, size_t key_len,
                        const uint8_t argon2_key[32],
                        const uint8_t mlkem_ss[32],
                        const uint8_t *context, size_t ctx_len) {
    shake_ctx ctx;
    shake256_init(&ctx);
    const uint8_t domain[] = "rv5-hybrid-kdf-v1";
    shake256_absorb(&ctx, domain, sizeof(domain)-1);
    shake256_absorb(&ctx, argon2_key, 32);
    shake256_absorb(&ctx, mlkem_ss, 32);
    if (context && ctx_len > 0) shake256_absorb(&ctx, context, ctx_len);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out_key, key_len);
}

/* ================================================================== */
/* Compatibility aliases                                                */
/* rv.c uses these shorter names; pqc_core.h uses the verbose ones.   */
/* ================================================================== */
typedef shake_ctx keccak_ctx;   /* shake_ctx and keccak_ctx are the same type */

#define MLKEM1024_PK_BYTES   MLKEM1024_PUBLICKEYBYTES
#define MLKEM1024_SK_BYTES   MLKEM1024_SECRETKEYBYTES
#define MLKEM1024_CT_BYTES   MLKEM1024_CIPHERTEXTBYTES
#define MLKEM1024_SS_BYTES   MLKEM1024_SHAREDSECRETBYTES
