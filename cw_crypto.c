// cw_crypto.c — см. cw_crypto.h
#include "cw_crypto.h"

#include <string.h>

#include "crypto-ops.h"
#include "keccak.h"
#include "blake2b.h"

// x25519.c
void cw_x25519_ladder(uint8_t *q, const uint8_t *e, const uint8_t *p);

// ---------------------------------------------------------------------------
// генераторы (src/crypto/generators.cpp)
// ---------------------------------------------------------------------------
const uint8_t CW_G[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 };
const uint8_t CW_H[32] = {
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94 };
const uint8_t CW_T[32] = {
    220, 66, 225, 211, 48, 123, 45, 75, 59, 2, 114, 154, 190, 87, 126, 35,
    29, 121, 71, 129, 65, 203, 91, 49, 12, 169, 250, 110, 18, 118, 22, 163 };
const uint8_t CW_U[32] = {
    138, 148, 142, 40, 84, 7, 58, 160, 188, 184, 47, 134, 60, 128, 134, 91,
    92, 201, 190, 23, 151, 35, 252, 28, 191, 28, 37, 184, 133, 89, 126, 84 };
const uint8_t CW_V[32] = {
    26, 66, 53, 9, 247, 103, 94, 145, 32, 17, 209, 75, 86, 16, 168, 87,
    221, 213, 136, 115, 52, 19, 181, 21, 224, 3, 188, 64, 85, 133, 91, 241 };
const uint8_t CW_IDENTITY[32] = { 1 };

void cw_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

// ---------------------------------------------------------------------------
// хеши
// ---------------------------------------------------------------------------
void cw_keccak(const void *data, size_t len, uint8_t out[32])
{
    keccak((const uint8_t *)data, len, out, 32);
}

void cw_hash_to_scalar(const void *data, size_t len, uint8_t out[32])
{
    cw_keccak(data, len, out);
    sc_reduce32(out);
}

void cw_blake2b_carrot(const void *key32, const void *data, size_t len,
                       uint8_t *out, size_t outlen)
{
    blake2b_param p;
    memset(&p, 0, sizeof(p));
    p.digest_length = (uint8_t)outlen;
    p.key_length = key32 ? 32 : 0;
    p.fanout = 1;
    p.depth = 1;
    memcpy(p.personal, "Monero", 6);

    blake2b_state st;
    blake2b_init_param(&st, &p);
    if (key32) {
        uint8_t block[BLAKE2B_BLOCKBYTES];
        memset(block, 0, sizeof(block));
        memcpy(block, key32, 32);
        blake2b_update(&st, block, sizeof(block));
        cw_wipe(block, sizeof(block));
    }
    blake2b_update(&st, data, len);
    blake2b_final(&st, out, outlen);
    cw_wipe(&st, sizeof(st));
}

void cw_derive_scalar(const void *key32, const void *data, size_t len, uint8_t out[32])
{
    uint8_t wide[64];
    cw_blake2b_carrot(key32, data, len, wide, 64);
    sc_reduce(wide);
    memcpy(out, wide, 32);
    cw_wipe(wide, sizeof(wide));
}

void cw_tr_init(cw_tr_t *t, const char *domain)
{
    size_t n = strlen(domain);
    t->buf[0] = (uint8_t)n;
    memcpy(t->buf + 1, domain, n);
    t->n = 1 + n;
}

void cw_tr_add(cw_tr_t *t, const void *data, size_t len)
{
    if (t->n + len > sizeof(t->buf)) return;   // транскрипты фиксированные, не случается
    memcpy(t->buf + t->n, data, len);
    t->n += len;
}

void cw_tr_u8(cw_tr_t *t, uint8_t v) { cw_tr_add(t, &v, 1); }

void cw_tr_u32(cw_tr_t *t, uint32_t v)
{
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    cw_tr_add(t, b, 4);
}

void cw_tr_u64(cw_tr_t *t, uint64_t v)
{
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
    cw_tr_add(t, b, 8);
}

void cw_tr_wipe(cw_tr_t *t) { cw_wipe(t, sizeof(*t)); }

// ---------------------------------------------------------------------------
// скаляры
// ---------------------------------------------------------------------------
void cw_sc_reduce64(uint8_t out[32], const uint8_t in[64])
{
    uint8_t t[64];
    memcpy(t, in, 64);
    sc_reduce(t);
    memcpy(out, t, 32);
    cw_wipe(t, sizeof(t));
}

void cw_sc_add(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]) { sc_add(r, a, b); }
void cw_sc_sub(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]) { sc_sub(r, a, b); }
void cw_sc_mul(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]) { sc_mul(r, a, b); }
void cw_sc_muladd(uint8_t r[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32]) { sc_muladd(r, a, b, c); }
void cw_sc_mulsub(uint8_t r[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32]) { sc_mulsub(r, a, b, c); }

void cw_sc_neg(uint8_t r[32], const uint8_t a[32])
{
    uint8_t z[32] = { 0 };
    sc_sub(r, z, a);
}

bool cw_sc_is_zero(const uint8_t a[32]) { return sc_isnonzero(a) == 0; }
bool cw_sc_is_canonical(const uint8_t a[32]) { return sc_check(a) == 0; }

void cw_sc_from_u64(uint8_t r[32], uint64_t v)
{
    memset(r, 0, 32);
    for (int i = 0; i < 8; i++) r[i] = (uint8_t)(v >> (8 * i));
}

void cw_sc_hedged(uint8_t out[32], const void *secret, size_t secret_len,
                  const void *ctx, size_t ctx_len, uint32_t counter)
{
    // k = H_64("CW hedged nonce" || secret || ctx || counter || rnd) mod l
    for (;;) {
        uint8_t rnd[32];
        cw_random(rnd, sizeof(rnd));

        blake2b_param p;
        memset(&p, 0, sizeof(p));
        p.digest_length = 64;
        p.fanout = 1;
        p.depth = 1;
        memcpy(p.personal, "CW hedged nonce", 15);
        blake2b_state st;
        blake2b_init_param(&st, &p);
        blake2b_update(&st, secret, secret_len);
        blake2b_update(&st, ctx, ctx_len);
        uint8_t c[4] = { (uint8_t)counter, (uint8_t)(counter >> 8),
                         (uint8_t)(counter >> 16), (uint8_t)(counter >> 24) };
        blake2b_update(&st, c, 4);
        blake2b_update(&st, rnd, sizeof(rnd));
        uint8_t wide[64];
        blake2b_final(&st, wide, 64);
        cw_wipe(&st, sizeof(st));
        cw_wipe(rnd, sizeof(rnd));
        sc_reduce(wide);
        memcpy(out, wide, 32);
        cw_wipe(wide, sizeof(wide));
        if (!cw_sc_is_zero(out)) return;
        counter ^= 0x80000000u;
    }
}

// ---------------------------------------------------------------------------
// точки
// ---------------------------------------------------------------------------
bool cw_pt_valid(const uint8_t P[32])
{
    ge_p3 p;
    return ge_frombytes_vartime(&p, P) == 0;
}

void cw_pt_base(uint8_t out[32], const uint8_t s[32])
{
    ge_p3 p;
    ge_scalarmult_base(&p, s);
    ge_p3_tobytes(out, &p);
}

bool cw_pt_mul(uint8_t out[32], const uint8_t s[32], const uint8_t P[32])
{
    ge_p3 p;
    if (ge_frombytes_vartime(&p, P) != 0) return false;
    ge_scalarmult_p3(&p, s, &p);
    ge_p3_tobytes(out, &p);
    return true;
}

bool cw_pt_mul8(uint8_t out[32], const uint8_t P[32])
{
    ge_p3 p;
    if (ge_frombytes_vartime(&p, P) != 0) return false;
    ge_p2 p2;
    ge_p3_to_p2(&p2, &p);
    ge_p1p1 r;
    ge_mul8(&r, &p2);
    ge_p1p1_to_p2(&p2, &r);
    ge_tobytes(out, &p2);
    return true;
}

bool cw_pt_add(uint8_t out[32], const uint8_t P[32], const uint8_t Q[32])
{
    ge_p3 p, q;
    if (ge_frombytes_vartime(&p, P) != 0) return false;
    if (ge_frombytes_vartime(&q, Q) != 0) return false;
    ge_cached qc;
    ge_p3_to_cached(&qc, &q);
    ge_p1p1 r;
    ge_add(&r, &p, &qc);
    ge_p2 r2;
    ge_p1p1_to_p2(&r2, &r);
    ge_tobytes(out, &r2);
    return true;
}

bool cw_pt_sub(uint8_t out[32], const uint8_t P[32], const uint8_t Q[32])
{
    ge_p3 p, q;
    if (ge_frombytes_vartime(&p, P) != 0) return false;
    if (ge_frombytes_vartime(&q, Q) != 0) return false;
    ge_cached qc;
    ge_p3_to_cached(&qc, &q);
    ge_p1p1 r;
    ge_sub(&r, &p, &qc);
    ge_p2 r2;
    ge_p1p1_to_p2(&r2, &r);
    ge_tobytes(out, &r2);
    return true;
}

bool cw_pt_mul2(uint8_t out[32], const uint8_t a[32], const uint8_t P[32],
                const uint8_t b[32], const uint8_t Q[32])
{
    uint8_t aP[32], bQ[32];
    if (!cw_pt_mul(aP, a, P)) return false;
    if (!cw_pt_mul(bQ, b, Q)) return false;
    return cw_pt_add(out, aP, bQ);
}

void cw_pt_gt(uint8_t out[32], const uint8_t x[32], const uint8_t y[32])
{
    ge_p3 T;
    ge_frombytes_vartime(&T, CW_T);
    ge_p2 r;
    ge_double_scalarmult_base_vartime(&r, y, &T, x);   // y*T + x*G
    ge_tobytes(out, &r);
}

bool cw_pt_in_main_subgroup(const uint8_t P[32])
{
    static const uint8_t l[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };
    ge_p3 p;
    if (ge_frombytes_vartime(&p, P) != 0) return false;
    ge_scalarmult_p3(&p, l, &p);
    return ge_p3_is_point_at_infinity_vartime(&p) != 0;
}

bool cw_pt_eq(const uint8_t a[32], const uint8_t b[32])
{
    uint8_t d = 0;
    for (int i = 0; i < 32; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

void cw_commit(uint8_t out[32], uint64_t amount, const uint8_t mask[32])
{
    uint8_t a[32];
    cw_sc_from_u64(a, amount);
    ge_p3 H;
    ge_frombytes_vartime(&H, CW_H);
    ge_p2 r;
    ge_double_scalarmult_base_vartime(&r, a, &H, mask);   // a*H + mask*G
    ge_tobytes(out, &r);
}

// ---------------------------------------------------------------------------
// hash-to-point (src/crypto/crypto.cpp)
// ---------------------------------------------------------------------------
static void fromfe_mul8_p3(ge_p3 *out, const uint8_t h[32])
{
    ge_p2 p;
    ge_fromfe_frombytes_vartime(&p, h);
    ge_p1p1 p1;
    ge_mul8(&p1, &p);
    ge_p1p1_to_p3(out, &p1);
}

void cw_hp_biased(uint8_t out[32], const uint8_t P[32])
{
    uint8_t h[32];
    cw_keccak(P, 32, h);
    ge_p3 r;
    fromfe_mul8_p3(&r, h);
    ge_p3_tobytes(out, &r);
}

void cw_hp_unbiased(uint8_t out[32], const void *pre, size_t len)
{
    uint8_t h[64];
    cw_blake2b_carrot(NULL, pre, len, h, 64);
    ge_p3 a, b;
    fromfe_mul8_p3(&a, h);
    fromfe_mul8_p3(&b, h + 32);
    ge_cached bc;
    ge_p3_to_cached(&bc, &b);
    ge_p1p1 s;
    ge_add(&s, &a, &bc);
    ge_p3 r;
    ge_p1p1_to_p3(&r, &s);
    ge_p3_tobytes(out, &r);
}

void cw_ki_generator(uint8_t out[32], const uint8_t O[32], bool biased)
{
    if (biased) cw_hp_biased(out, O);
    else        cw_hp_unbiased(out, O, 32);
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------
void cw_x25519_base(uint8_t out[32], const uint8_t scalar[32])
{
    static const uint8_t nine[32] = { 9 };
    cw_x25519_ladder(out, scalar, nine);
}

void cw_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32])
{
    cw_x25519_ladder(out, scalar, u);
}

bool cw_ed_to_x25519(uint8_t out[32], const uint8_t ed[32])
{
    return edwards_bytes_to_x25519_vartime(out, ed) == 0;
}

bool cw_ed_mul_to_x25519(uint8_t out[32], const uint8_t s[32], const uint8_t ed[32])
{
    ge_p3 p;
    if (ge_frombytes_vartime(&p, ed) != 0) return false;
    ge_scalarmult_p3(&p, s, &p);
    ge_p3_to_x25519(out, &p);
    return true;
}

// ---------------------------------------------------------------------------
// CryptoNote
// ---------------------------------------------------------------------------
bool cw_key_derivation(uint8_t out[32], const uint8_t R[32], const uint8_t k[32])
{
    ge_p3 p;
    if (ge_frombytes_vartime(&p, R) != 0) return false;
    ge_p2 p2;
    ge_scalarmult(&p2, k, &p);
    ge_p1p1 p1;
    ge_mul8(&p1, &p2);
    ge_p1p1_to_p2(&p2, &p1);
    ge_tobytes(out, &p2);
    return true;
}

static size_t put_varint(uint8_t *out, uint64_t v)
{
    size_t n = 0;
    while (v >= 0x80) { out[n++] = (uint8_t)(v | 0x80); v >>= 7; }
    out[n++] = (uint8_t)v;
    return n;
}

void cw_derivation_to_scalar(uint8_t out[32], const uint8_t D[32], uint64_t idx)
{
    uint8_t buf[32 + 10];
    memcpy(buf, D, 32);
    size_t n = 32 + put_varint(buf + 32, idx);
    cw_hash_to_scalar(buf, n, out);
    cw_wipe(buf, sizeof(buf));
}

void cw_legacy_subaddr_ext(uint8_t out[32], const uint8_t k_view[32], uint32_t major, uint32_t minor)
{
    // m = H_s("SubAddr\0" || k_v || major || minor)
    uint8_t buf[8 + 32 + 8];
    memcpy(buf, "SubAddr", 8);   // включая '\0'
    memcpy(buf + 8, k_view, 32);
    for (int i = 0; i < 4; i++) buf[40 + i] = (uint8_t)(major >> (8 * i));
    for (int i = 0; i < 4; i++) buf[44 + i] = (uint8_t)(minor >> (8 * i));
    cw_hash_to_scalar(buf, sizeof(buf), out);
    cw_wipe(buf, sizeof(buf));
}

void cw_generate_signature(uint8_t sig[64], const uint8_t hash[32],
                           const uint8_t pub[32], const uint8_t sec[32])
{
    uint8_t k[32], buf[96];
    cw_sc_hedged(k, sec, 32, hash, 32, 0x5349474Eu);
    memcpy(buf, hash, 32);
    memcpy(buf + 32, pub, 32);
    cw_pt_base(buf + 64, k);
    cw_hash_to_scalar(buf, 96, sig);              // c
    sc_mulsub(sig + 32, sig, sec, k);             // r = k - c*sec
    cw_wipe(k, sizeof(k));
}

bool cw_check_signature(const uint8_t sig[64], const uint8_t hash[32], const uint8_t pub[32])
{
    ge_p3 P;
    if (ge_frombytes_vartime(&P, pub) != 0) return false;
    if (sc_check(sig) != 0 || sc_check(sig + 32) != 0) return false;
    if (!sc_isnonzero(sig)) return false;
    ge_p2 R;
    ge_double_scalarmult_base_vartime(&R, sig, &P, sig + 32);   // c*P + r*G
    uint8_t buf[96], c[32];
    memcpy(buf, hash, 32);
    memcpy(buf + 32, pub, 32);
    ge_tobytes(buf + 64, &R);
    if (cw_pt_eq(buf + 64, CW_IDENTITY)) return false;
    cw_hash_to_scalar(buf, 96, c);
    sc_sub(c, c, sig);
    return sc_isnonzero(c) == 0;
}

void cw_ring1_signature(uint8_t sig[64], const uint8_t hash[32], const uint8_t key_image[32],
                        const uint8_t O[32], const uint8_t x[32])
{
    uint8_t k[32], buf[96], hp[32];
    cw_sc_hedged(k, x, 32, key_image, 32, 0x52494E47u);
    memcpy(buf, hash, 32);
    cw_pt_base(buf + 32, k);                      // a = k*G
    cw_hp_biased(hp, O);
    cw_pt_mul(buf + 64, k, hp);                   // b = k*Hp(O)
    cw_hash_to_scalar(buf, 96, sig);              // c = H(...) - 0
    sc_mulsub(sig + 32, sig, x, k);               // r = k - c*x
    cw_wipe(k, sizeof(k));
}

bool cw_ring1_check(const uint8_t sig[64], const uint8_t hash[32], const uint8_t key_image[32],
                    const uint8_t O[32])
{
    if (sc_check(sig) != 0 || sc_check(sig + 32) != 0) return false;
    uint8_t buf[96], hp[32], c[32];
    memcpy(buf, hash, 32);
    if (!cw_pt_mul2(buf + 32, sig, O, sig + 32, CW_G)) return false;   // c*O + r*G
    cw_hp_biased(hp, O);
    if (!cw_pt_mul2(buf + 64, sig + 32, hp, sig, key_image)) return false; // r*Hp + c*L
    cw_hash_to_scalar(buf, 96, c);
    sc_sub(c, c, sig);
    return sc_isnonzero(c) == 0;
}
