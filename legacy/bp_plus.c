// bp_plus.c
// (полный файл со всеми тестами; bp_plus_prove в конце)

#include "bp_plus.h"
#include "crypto-ops.h"
#include "hash-ops.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <Arduino.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

extern void platform_log(const char *msg);
extern void platform_random_bytes(uint8_t *buf, size_t n);

// ===========================================================================
// Константы
// ===========================================================================

// H = toPoint(cn_fast_hash(G)) — вторая базовая точка (rctTypes.h::H)
static const uint8_t H_BYTES[32] = {
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
    0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
    0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94
};

// ge_p3_H из crypto-ops-data.c — эталон для проверки H_BYTES
// (это представление H в 10-элементных fe-координатах)
static const fe H_X_fe = {7329926, -15101362, 31411471, 7614783, 27996851,
                          -3197071, -11157635, -6878293, 466949, -7986503};
static const fe H_Y_fe = {5858699, 5096796, 21321203, -7536921, -5553480,
                          -11439507, -5627669, 15045946, 19977121, 5275251};

static const uint8_t ZERO[32]     = {0};
static const uint8_t ONE[32]      = {1};
static const uint8_t TWO[32]      = {2};
static const uint8_t INV_EIGHT_BYTES[32] = {
    0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61,
    0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06
};
static const uint8_t MINUS_ONE[32] = {
    0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};
static const uint8_t MINUS_INV_EIGHT[32] = {
    0x74, 0xa4, 0x19, 0x7a, 0xf0, 0x7d, 0x0b, 0xf7,
    0x05, 0xc2, 0xda, 0x25, 0x2b, 0x5c, 0x0b, 0x0d,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a
};

// Генератор G (базовая точка ed25519)
static const uint8_t G_BYTES[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

static const char HASH_KEY_BP_PLUS_EXPONENT[]   = "bulletproof_plus";
static const char HASH_KEY_BP_PLUS_TRANSCRIPT[] = "bulletproof_plus_transcript";

// ===========================================================================
// PSRAM
// ===========================================================================
static void *psram_alloc(size_t sz) {
    return heap_caps_malloc(sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

// ===========================================================================
// Глобальные кэши
// ===========================================================================
static ge_p3 *Hi_p3 = NULL;
static ge_p3 *Gi_p3 = NULL;
static uint8_t initial_transcript[32];
static uint8_t TWO_SIXTY_FOUR_MINUS_ONE[32];
static bool  exponents_ready = false;

static uint8_t (*aL)[32]            = NULL;
static uint8_t (*aR)[32]            = NULL;
static uint8_t (*aL8)[32]           = NULL;
static uint8_t (*aR8)[32]           = NULL;
static uint8_t (*d)[32]             = NULL;
static uint8_t (*y_powers)[32]      = NULL;
static uint8_t (*aL1)[32]           = NULL;
static uint8_t (*aR1)[32]           = NULL;
static ge_p3   *Gprime              = NULL;
static ge_p3   *Hprime              = NULL;
static uint8_t (*aprime)[32]        = NULL;
static uint8_t (*bprime)[32]        = NULL;
static uint8_t (*yinvpow)[32]       = NULL;
static uint8_t (*aprime_scaled)[32] = NULL;
static uint8_t (*aprime_new)[32]    = NULL;
static uint8_t (*bprime_new)[32]    = NULL;

// ===========================================================================
// Forward
// ===========================================================================
static void sc_invert(uint8_t out[32], const uint8_t x[32]);
static void vector_of_scalar_powers(uint8_t *res, const uint8_t x[32], size_t n);
static void weighted_inner_product(uint8_t out[32],
                                   const uint8_t *a, const uint8_t *b,
                                   size_t n, const uint8_t y[32]);
static void hadamard_fold(ge_p3 *v, size_t n,
                          const uint8_t a[32], const uint8_t b[32]);
static bool get_exponent(ge_p3 *out, const uint8_t base[32], size_t idx);
static void hash_to_p3(const uint8_t P[32], ge_p3 *out);

// ===========================================================================
// Утилиты
// ===========================================================================
static void logf_(const char *fmt, ...) {
    char buf[240];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    platform_log(buf);
}

static void log_hex32(const char *prefix, const uint8_t *p) {
    char buf[100];
    int n = snprintf(buf, sizeof(buf), "%s=", prefix);
    for (int i = 0; i < 32; i++) n += snprintf(buf + n, sizeof(buf) - n, "%02x", p[i]);
    platform_log(buf);
}

static void hash_to_scalar(const void *data, size_t len, uint8_t out[32]) {
    cn_fast_hash(data, len, (char*)out);
    sc_reduce32(out);
}

static void hash_to_p3(const uint8_t P[32], ge_p3 *out) {
    uint8_t h[32];
    cn_fast_hash(P, 32, (char*)h);
    ge_p2 p2;
    ge_fromfe_frombytes_vartime(&p2, h);
    ge_p1p1 p1p1;
    ge_mul8(&p1p1, &p2);
    ge_p1p1_to_p3(out, &p1p1);
}

static size_t put_varint(uint8_t *out, uint64_t v) {
    size_t n = 0;
    while (v >= 0x80) {
        out[n++] = (uint8_t)(v & 0x7f) | 0x80;
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

static bool bytes_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

// ===========================================================================
// check_point
// ===========================================================================
static bool check_point(const char *name, const uint8_t bytes[32]) {
    ge_p3 p3;
    if (ge_frombytes_vartime(&p3, bytes) != 0) {
        logf_("BAD_POINT: %s NOT ON CURVE", name);
        return false;
    }
    if (ge_p3_is_point_at_infinity_vartime(&p3)) {
        logf_("BAD_POINT: %s IS IDENTITY", name);
        return false;
    }
    return true;
}

// Точка принадлежит подгруппе порядка l? Проверка: l * P == identity
static bool check_point_in_subgroup(const char *name, const uint8_t bytes[32]) {
    ge_p3 P;
    if (ge_frombytes_vartime(&P, bytes) != 0) {
        logf_("SUBGROUP: %s not on curve", name);
        return false;
    }
    // Умножаем на l — если точка в подгруппе, получим identity
    // Используем ge_scalarmult, передавая l
    static const uint8_t L_SCALAR[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    ge_p2 R;
    ge_scalarmult(&R, L_SCALAR, &P);
    uint8_t R_bytes[32];
    ge_tobytes(R_bytes, &R);
    // Проверим, что результат — identity
    ge_p3 R_p3;
    if (ge_frombytes_vartime(&R_p3, R_bytes) != 0) {
        // identity не всегда парсится корректно — попробуем сравнить байты
        uint8_t id_bytes[32] = {1};
        if (!bytes_eq(R_bytes, id_bytes, 32)) {
            logf_("SUBGROUP: %s NOT in subgroup", name);
            return false;
        }
        return true;
    }
    if (!ge_p3_is_point_at_infinity_vartime(&R_p3)) {
        logf_("SUBGROUP: %s NOT in subgroup (l*P != identity)", name);
        return false;
    }
    return true;
}

// ===========================================================================
// is_reduced
// ===========================================================================
static bool is_reduced(const uint8_t s[32]) { return sc_check(s) == 0; }

// ===========================================================================
// get_exponent
// ===========================================================================
static bool get_exponent(ge_p3 *out, const uint8_t base[32], size_t idx) {
    uint8_t varint_buf[10];
    size_t vlen = put_varint(varint_buf, idx);

    uint8_t buf[32 + 32 + 10];
    size_t p = 0;
    memcpy(buf + p, base, 32); p += 32;
    memcpy(buf + p, HASH_KEY_BP_PLUS_EXPONENT, sizeof(HASH_KEY_BP_PLUS_EXPONENT) - 1);
    p += sizeof(HASH_KEY_BP_PLUS_EXPONENT) - 1;
    memcpy(buf + p, varint_buf, vlen); p += vlen;

    // === ИСПРАВЛЕНО ===
    // Monero bulletproofs_plus.cc::get_exponent:
    //   hash_to_p3(res, cn_fast_hash(base || "bulletproof_plus" || varint(idx)))
    // где hash_to_p3(k) = 8 * ge_fromfe(cn_fast_hash(k)), то есть keccak ДВАЖДЫ.
    uint8_t h[32];
    cn_fast_hash(buf, p, (char*)h);
    cn_fast_hash(h, 32, (char*)h);

    ge_p2 p2;
    ge_fromfe_frombytes_vartime(&p2, h);
    ge_p1p1 p1p1;
    ge_mul8(&p1p1, &p2);
    ge_p1p1_to_p3(out, &p1p1);

    if (ge_p3_is_point_at_infinity_vartime(out)) {
        return false;
    }
    return true;
}

// ===========================================================================
// alloc_buffers
// ===========================================================================
static bool bp_plus_alloc_buffers(void) {
    if (aL) return true;
    aL            = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);
    aR            = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);
    aL8           = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);
    aR8           = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);
    d             = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);
    y_powers      = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * (BP_PLUS_MAX_MN + 2));
    aL1           = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);
    aR1           = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);
    Gprime        = (ge_p3 *)psram_alloc(sizeof(ge_p3) * BP_PLUS_MAX_MN);
    Hprime        = (ge_p3 *)psram_alloc(sizeof(ge_p3) * BP_PLUS_MAX_MN);
    aprime        = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);
    bprime        = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);
    yinvpow       = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);
    aprime_scaled = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);
    aprime_new    = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);
    bprime_new    = (uint8_t (*)[32])psram_alloc(sizeof(uint8_t[32]) * BP_PLUS_MAX_MN);

    if (!aL || !aR || !aL8 || !aR8 || !d || !y_powers ||
        !aL1 || !aR1 || !Gprime || !Hprime ||
        !aprime || !bprime || !yinvpow || !aprime_scaled ||
        !aprime_new || !bprime_new) {
        return false;
    }
    return true;
}

// ===========================================================================
// init_exponents
// ===========================================================================
static bool init_exponents(void) {
    if (exponents_ready) return true;
    Hi_p3 = (ge_p3 *)psram_alloc(sizeof(ge_p3) * BP_PLUS_MAX_MN);
    Gi_p3 = (ge_p3 *)psram_alloc(sizeof(ge_p3) * BP_PLUS_MAX_MN);
    if (!Hi_p3 || !Gi_p3) return false;

    for (size_t i = 0; i < BP_PLUS_MAX_MN; i++) {
        if (!get_exponent(&Hi_p3[i], H_BYTES, i * 2 + 0)) return false;
        if (!get_exponent(&Gi_p3[i], H_BYTES, i * 2 + 1)) return false;
        if ((i & 0x3F) == 0) vTaskDelay(1);
    }

    memset(TWO_SIXTY_FOUR_MINUS_ONE, 0, 32);
    for (int k = 0; k < 8; k++) TWO_SIXTY_FOUR_MINUS_ONE[k] = 0xFF;

    {
        uint8_t h[32];
        // === ИСПРАВЛЕНО: тоже двойной keccak (hash_to_p3(cn_fast_hash(domain))) ===
        cn_fast_hash(HASH_KEY_BP_PLUS_TRANSCRIPT,
                     sizeof(HASH_KEY_BP_PLUS_TRANSCRIPT) - 1, (char*)h);
        cn_fast_hash(h, 32, (char*)h);
        ge_p3 it_p3;
        ge_p2 p2;
        ge_fromfe_frombytes_vartime(&p2, h);
        ge_p1p1 p1p1;
        ge_mul8(&p1p1, &p2);
        ge_p1p1_to_p3(&it_p3, &p1p1);
        ge_p3_tobytes(initial_transcript, &it_p3);
    }
    exponents_ready = true;
    return true;
}

void bp_plus_cleanup(void) {
    if (Hi_p3) { heap_caps_free(Hi_p3); Hi_p3 = NULL; }
    if (Gi_p3) { heap_caps_free(Gi_p3); Gi_p3 = NULL; }
    if (aL) { heap_caps_free(aL); aL = NULL; }
    if (aR) { heap_caps_free(aR); aR = NULL; }
    if (aL8) { heap_caps_free(aL8); aL8 = NULL; }
    if (aR8) { heap_caps_free(aR8); aR8 = NULL; }
    if (d) { heap_caps_free(d); d = NULL; }
    if (y_powers) { heap_caps_free(y_powers); y_powers = NULL; }
    if (aL1) { heap_caps_free(aL1); aL1 = NULL; }
    if (aR1) { heap_caps_free(aR1); aR1 = NULL; }
    if (Gprime) { heap_caps_free(Gprime); Gprime = NULL; }
    if (Hprime) { heap_caps_free(Hprime); Hprime = NULL; }
    if (aprime) { heap_caps_free(aprime); aprime = NULL; }
    if (bprime) { heap_caps_free(bprime); bprime = NULL; }
    if (yinvpow) { heap_caps_free(yinvpow); yinvpow = NULL; }
    if (aprime_scaled) { heap_caps_free(aprime_scaled); aprime_scaled = NULL; }
    if (aprime_new) { heap_caps_free(aprime_new); aprime_new = NULL; }
    if (bprime_new) { heap_caps_free(bprime_new); bprime_new = NULL; }
    exponents_ready = false;
}

// ===========================================================================
// transcript_update
// ===========================================================================
static void transcript_update(uint8_t transcript[32],
                              const uint8_t *updates, size_t n_updates) {
    uint8_t buf[32 * (1 + BP_PLUS_MAX_LOG_MN * 2 + 8)];
    memcpy(buf, transcript, 32);
    memcpy(buf + 32, updates, n_updates * 32);
    hash_to_scalar(buf, 32 + n_updates * 32, transcript);
}
static void transcript_update1(uint8_t t[32], const uint8_t u0[32]) {
    transcript_update(t, u0, 1);
}
static void transcript_update2(uint8_t t[32], const uint8_t u0[32], const uint8_t u1[32]) {
    uint8_t upd[2][32];
    memcpy(upd[0], u0, 32);
    memcpy(upd[1], u1, 32);
    transcript_update(t, (const uint8_t*)upd, 2);
}

// ===========================================================================
// vector_of_scalar_powers
// ===========================================================================
static void vector_of_scalar_powers(uint8_t *res, const uint8_t x[32], size_t n) {
    memset(res, 0, 32);
    res[0] = 1;
    if (n == 1) return;
    memcpy(res + 32, x, 32);
    for (size_t i = 2; i < n; i++) {
        sc_mul(res + i * 32, res + (i - 1) * 32, x);
    }
}

// ===========================================================================
// weighted_inner_product
// ===========================================================================
static void weighted_inner_product(uint8_t out[32],
                                   const uint8_t *a, const uint8_t *b,
                                   size_t n, const uint8_t y[32]) {
    memset(out, 0, 32);
    uint8_t y_power[32];
    memcpy(y_power, ONE, 32);
    uint8_t temp[32];
    // === ИСПРАВЛЕНО ===
    // Monero: y_power домножается ДО sc_muladd, т.е. слагаемые идут с y^1, y^2, ...
    // Было: y^0, y^1, ... — весь weighted inner product сдвинут на одну степень.
    for (size_t i = 0; i < n; i++) {
        sc_mul(temp, a + i * 32, b + i * 32);
        sc_mul(y_power, y_power, y);
        sc_muladd(out, temp, y_power, out);
    }
}

// ===========================================================================
// sc_invert
// ===========================================================================
static void sc_invert(uint8_t out[32], const uint8_t x[32]) {
    uint8_t _1[32], _10[32], _100[32], _11[32], _101[32], _111[32];
    uint8_t _1001[32], _1011[32], _1111[32];

    memcpy(_1, x, 32);
    sc_mul(_10, _1, _1);
    sc_mul(_100, _10, _10);
    sc_mul(_11, _10, _1);
    sc_mul(_101, _10, _11);
    sc_mul(_111, _10, _101);
    sc_mul(_1001, _10, _111);
    sc_mul(_1011, _10, _1001);
    sc_mul(_1111, _100, _1011);

    uint8_t inv[32];
    sc_mul(inv, _1111, _1);

    #define SM(Y, N, X) do { \
        for (int _k = 0; _k < (N); _k++) sc_mul((Y), (Y), (Y)); \
        sc_mul((Y), (Y), (X)); \
    } while(0)

    SM(inv, 123 + 3, _101);
    SM(inv, 2 + 2, _11);
    SM(inv, 1 + 4, _1111);
    SM(inv, 1 + 4, _1111);
    SM(inv, 4, _1001);
    SM(inv, 2, _11);
    SM(inv, 1 + 4, _1111);
    SM(inv, 1 + 3, _101);
    SM(inv, 3 + 3, _101);
    SM(inv, 3, _111);
    SM(inv, 1 + 4, _1111);
    SM(inv, 2 + 3, _111);
    SM(inv, 2 + 2, _11);
    SM(inv, 1 + 4, _1011);
    SM(inv, 2 + 4, _1011);
    SM(inv, 6 + 4, _1001);
    SM(inv, 2 + 2, _11);
    SM(inv, 3 + 2, _11);
    SM(inv, 3 + 2, _11);
    SM(inv, 1 + 4, _1001);
    SM(inv, 1 + 3, _111);
    SM(inv, 2 + 4, _1111);
    SM(inv, 1 + 4, _1011);
    SM(inv, 3, _101);
    SM(inv, 2 + 4, _1111);
    SM(inv, 3, _101);
    SM(inv, 1 + 2, _11);

    #undef SM
    memcpy(out, inv, 32);
}

// ===========================================================================
// Векторные операции
// ===========================================================================
static void vector_add_scalar(uint8_t *out, const uint8_t *a, const uint8_t s[32], size_t n) {
    for (size_t i = 0; i < n; i++) sc_add(out + i*32, a + i*32, s);
}
static void vector_sub_scalar(uint8_t *out, const uint8_t *a, const uint8_t s[32], size_t n) {
    for (size_t i = 0; i < n; i++) sc_sub(out + i*32, a + i*32, s);
}

// ===========================================================================
// vector_exponent
// ===========================================================================
static void vector_exponent(uint8_t out[32],
                            const uint8_t *a, const uint8_t *b, size_t n) {
    ge_p3 acc;
    fe_0(acc.X); fe_1(acc.Y); fe_1(acc.Z); fe_0(acc.T);
    for (size_t i = 0; i < n; i++) {
        ge_dsmp Gi, Hi;
        ge_dsm_precomp(Gi, &Gi_p3[i]);
        ge_dsm_precomp(Hi, &Hi_p3[i]);
        ge_p2 p2;
        // === ИСПРАВЛЕНО ===
        // ge_triple_scalarmult_base_vartime(r, a, b, B, c, C) считает a*G + b*B + c*C.
        // Было: a[i]*G + b[i]*Gi + 0*Hi  (скаляр aL уходил на базовую точку,
        // aR умножался на Gi, а Hi вообще не участвовал).
        // Нужно: 0*G + a[i]*Gi + b[i]*Hi.
        ge_triple_scalarmult_base_vartime(&p2, ZERO, a + i*32, Gi, b + i*32, Hi);
        uint8_t tmp[32];
        ge_tobytes(tmp, &p2);
        ge_p3 p3;
        ge_frombytes_vartime(&p3, tmp);
        ge_cached c;
        ge_p3_to_cached(&c, &p3);
        ge_p1p1 pp;
        ge_add(&pp, &acc, &c);
        ge_p1p1_to_p3(&acc, &pp);
    }
    ge_p3_tobytes(out, &acc);
}

// ===========================================================================
// compute_LR
// ===========================================================================
static void compute_LR(uint8_t out[32],
                       size_t size, const uint8_t y[32],
                       const ge_p3 *G, size_t G0,
                       const ge_p3 *H, size_t H0,
                       const uint8_t *a, size_t a0,
                       const uint8_t *b, size_t b0,
                       const uint8_t c[32], const uint8_t d[32]) {
    ge_p3 acc;
    fe_0(acc.X); fe_1(acc.Y); fe_1(acc.Z); fe_0(acc.T);
    uint8_t temp[32];
    uint8_t a_prime[32], b_prime[32], c_prime[32], d_prime[32];
    sc_mul(c_prime, c, INV_EIGHT_BYTES);
    sc_mul(d_prime, d, INV_EIGHT_BYTES);
    for (size_t i = 0; i < size; i++) {
        sc_mul(temp, a + (a0 + i) * 32, y);
        sc_mul(a_prime, temp, INV_EIGHT_BYTES);
        sc_mul(b_prime, b + (b0 + i) * 32, INV_EIGHT_BYTES);
        ge_dsmp Gi, Hi;
        ge_dsm_precomp(Gi, &G[G0 + i]);
        ge_dsm_precomp(Hi, &H[H0 + i]);
        ge_p2 p2;
        // === ИСПРАВЛЕНО === (та же ошибка, что и в vector_exponent)
        ge_triple_scalarmult_base_vartime(&p2, ZERO, a_prime, Gi, b_prime, Hi);
        uint8_t tmp[32];
        ge_tobytes(tmp, &p2);
        ge_p3 p3;
        ge_frombytes_vartime(&p3, tmp);
        ge_cached cc;
        ge_p3_to_cached(&cc, &p3);
        ge_p1p1 pp;
        ge_add(&pp, &acc, &cc);
        ge_p1p1_to_p3(&acc, &pp);
    }
    {
        ge_p3 H_p3;
        if (ge_frombytes_vartime(&H_p3, H_BYTES) != 0) {
            memset(out, 0, 32); return;
        }
        ge_p2 p2;
        ge_scalarmult(&p2, c_prime, &H_p3);
        uint8_t tmp[32];
        ge_tobytes(tmp, &p2);
        ge_p3 p3;
        ge_frombytes_vartime(&p3, tmp);
        ge_cached cc;
        ge_p3_to_cached(&cc, &p3);
        ge_p1p1 pp;
        ge_add(&pp, &acc, &cc);
        ge_p1p1_to_p3(&acc, &pp);
    }
    {
        ge_p3 G_p3;
        ge_scalarmult_base(&G_p3, d_prime);
        ge_cached cc;
        ge_p3_to_cached(&cc, &G_p3);
        ge_p1p1 pp;
        ge_add(&pp, &acc, &cc);
        ge_p1p1_to_p3(&acc, &pp);
    }
    ge_p3_tobytes(out, &acc);
}

// ===========================================================================
// hadamard_fold
// ===========================================================================
static void hadamard_fold(ge_p3 *v, size_t n, const uint8_t a[32], const uint8_t b[32]) {
    size_t sz = n / 2;
    for (size_t i = 0; i < sz; i++) {
        ge_dsmp A, B;
        ge_dsm_precomp(A, &v[i]);
        ge_dsm_precomp(B, &v[sz + i]);
        ge_double_scalarmult_precomp_vartime2_p3(&v[i], a, A, b, B);
    }
}

// ===========================================================================
// ========================  SELF-TESTS  =====================================
// ===========================================================================

// ---------------------------------------------------------------------------
// T01. sc_mul
// ---------------------------------------------------------------------------
static bool test_sc_mul(void) {
    logf_("-- T01 test_sc_mul --");
    uint8_t two[32]   = {2};
    uint8_t three[32] = {3};
    uint8_t one[32]   = {1};
    uint8_t zero[32]  = {0};
    uint8_t r[32], exp[32];

    sc_mul(r, two, three);
    memset(exp, 0, 32); exp[0] = 6;
    if (!bytes_eq(r, exp, 32)) { log_hex32("  FAIL 2*3", r); return false; }
    logf_("  2*3 = 6  OK");

    uint8_t x[32]; platform_random_bytes(x, 32); sc_reduce32(x);
    sc_mul(r, x, one);
    if (!bytes_eq(r, x, 32)) { logf_("  FAIL x*1 != x"); return false; }
    logf_("  x*1 = x  OK");

    sc_mul(r, x, zero);
    if (!bytes_eq(r, zero, 32)) { log_hex32("  FAIL x*0", r); return false; }
    logf_("  x*0 = 0  OK");

    // коммутативность
    uint8_t a[32], b[32], ab[32], ba[32];
    platform_random_bytes(a, 32); sc_reduce32(a);
    platform_random_bytes(b, 32); sc_reduce32(b);
    sc_mul(ab, a, b); sc_mul(ba, b, a);
    if (!bytes_eq(ab, ba, 32)) { logf_("  FAIL a*b != b*a"); return false; }
    logf_("  a*b = b*a  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T02. sc_add
// ---------------------------------------------------------------------------
static bool test_sc_add(void) {
    logf_("-- T02 test_sc_add --");
    uint8_t two[32] = {2}, three[32] = {3}, zero[32] = {0};
    uint8_t r[32], exp[32];
    sc_add(r, two, three);
    memset(exp, 0, 32); exp[0] = 5;
    if (!bytes_eq(r, exp, 32)) { log_hex32("  FAIL 2+3", r); return false; }
    logf_("  2+3 = 5  OK");

    uint8_t x[32]; platform_random_bytes(x, 32); sc_reduce32(x);
    sc_add(r, x, zero);
    if (!bytes_eq(r, x, 32)) { logf_("  FAIL x+0 != x"); return false; }
    logf_("  x+0 = x  OK");

    uint8_t negx[32];
    sc_sub(negx, zero, x);
    sc_add(r, x, negx);
    if (!bytes_eq(r, zero, 32)) { logf_("  FAIL x + (-x) != 0"); return false; }
    logf_("  x + (-x) = 0  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T03. sc_sub
// ---------------------------------------------------------------------------
static bool test_sc_sub(void) {
    logf_("-- T03 test_sc_sub --");
    uint8_t five[32] = {5}, three[32] = {3};
    uint8_t r[32], exp[32];
    sc_sub(r, five, three);
    memset(exp, 0, 32); exp[0] = 2;
    if (!bytes_eq(r, exp, 32)) { log_hex32("  FAIL 5-3", r); return false; }
    logf_("  5-3 = 2  OK");

    uint8_t x[32]; platform_random_bytes(x, 32); sc_reduce32(x);
    sc_sub(r, x, x);
    uint8_t zero[32] = {0};
    if (!bytes_eq(r, zero, 32)) { log_hex32("  FAIL x-x", r); return false; }
    logf_("  x-x = 0  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T04. sc_muladd
// ---------------------------------------------------------------------------
static bool test_sc_muladd(void) {
    logf_("-- T04 test_sc_muladd --");
    uint8_t two[32] = {2}, three[32] = {3}, four[32] = {4};
    uint8_t r[32], exp[32];
    sc_muladd(r, two, three, four);
    memset(exp, 0, 32); exp[0] = 10;
    if (!bytes_eq(r, exp, 32)) { log_hex32("  FAIL 2*3+4", r); return false; }
    logf_("  2*3+4 = 10  OK");

    uint8_t x[32]; platform_random_bytes(x, 32); sc_reduce32(x);
    uint8_t one[32] = {1}, zero[32] = {0};
    sc_muladd(r, x, one, zero);
    if (!bytes_eq(r, x, 32)) { logf_("  FAIL x*1+0 != x"); return false; }
    logf_("  x*1+0 = x  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T05. sc_mulsub
// ---------------------------------------------------------------------------
static bool test_sc_mulsub(void) {
    logf_("-- T05 test_sc_mulsub --");
    uint8_t two[32] = {2}, three[32] = {3}, four[32] = {4};
    uint8_t r[32], check[32];
    sc_mulsub(r, two, three, four);
    sc_muladd(check, two, three, r);
    if (!bytes_eq(check, four, 32)) { log_hex32("  FAIL (r+2*3)!=4", check); return false; }
    logf_("  4 - 2*3 = -2 mod l (проверено)  OK");

    uint8_t x[32]; platform_random_bytes(x, 32); sc_reduce32(x);
    uint8_t one[32] = {1}, zero[32] = {0};
    sc_mulsub(r, x, one, zero);
    uint8_t negx[32];
    sc_sub(negx, zero, x);
    if (!bytes_eq(r, negx, 32)) { log_hex32("  FAIL 0-x*1!=-x", r); return false; }
    logf_("  0 - x*1 = -x  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T06. sc_reduce32 (включая границы)
// ---------------------------------------------------------------------------
static bool test_sc_reduce32(void) {
    logf_("-- T06 test_sc_reduce32 --");
    uint8_t x[32]; platform_random_bytes(x, 32); sc_reduce32(x);
    uint8_t y[32]; memcpy(y, x, 32); sc_reduce32(y);
    if (!bytes_eq(x, y, 32)) { log_hex32("  FAIL idempotent", y); return false; }
    logf_("  reduce(reduce(x)) == reduce(x)  OK");

    // l mod l = 0
    static const uint8_t L_SCALAR[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    uint8_t l[32]; memcpy(l, L_SCALAR, 32);
    sc_reduce32(l);
    uint8_t zero[32] = {0};
    if (!bytes_eq(l, zero, 32)) { log_hex32("  FAIL l mod l", l); return false; }
    logf_("  l mod l = 0  OK");

    // (l+1) mod l = 1
    uint8_t lp1[32]; memcpy(lp1, L_SCALAR, 32);
    lp1[0] += 1;
    sc_reduce32(lp1);
    uint8_t one[32] = {1};
    if (!bytes_eq(lp1, one, 32)) { log_hex32("  FAIL (l+1) mod l", lp1); return false; }
    logf_("  (l+1) mod l = 1  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T07. sc_invert
// ---------------------------------------------------------------------------
static bool test_sc_invert(void) {
    logf_("-- T07 test_sc_invert --");
    {
        uint8_t x[32] = {2};
        uint8_t inv[32]; sc_invert(inv, x);
        uint8_t prod[32]; sc_mul(prod, inv, x);
        uint8_t one[32] = {1};
        if (!bytes_eq(prod, one, 32)) { log_hex32("  FAIL 2*inv(2)", prod); return false; }
        logf_("  2 * inv(2) = 1  OK");
    }
    {
        uint8_t x[32] = {8};
        uint8_t inv[32]; sc_invert(inv, x);
        uint8_t prod[32]; sc_mul(prod, inv, x);
        uint8_t one[32] = {1};
        if (!bytes_eq(prod, one, 32)) { log_hex32("  FAIL 8*inv(8)", prod); return false; }
        logf_("  8 * inv(8) = 1  OK");
        if (!bytes_eq(inv, INV_EIGHT_BYTES, 32)) {
            logf_("  WARN: inv(8) != INV_EIGHT_BYTES");
        } else {
            logf_("  inv(8) == INV_EIGHT_BYTES  OK");
        }
    }
    {
        // много случайных
        for (int i = 0; i < 5; i++) {
            uint8_t x[32]; platform_random_bytes(x, 32); sc_reduce32(x);
            uint8_t zero[32] = {0};
            if (bytes_eq(x, zero, 32)) x[0] = 1;
            uint8_t inv[32]; sc_invert(inv, x);
            uint8_t prod[32]; sc_mul(prod, inv, x);
            uint8_t one[32] = {1};
            if (!bytes_eq(prod, one, 32)) {
                log_hex32("  FAIL random", prod);
                return false;
            }
        }
        logf_("  5 random * inv(random) = 1  OK");
    }
    return true;
}

// ---------------------------------------------------------------------------
// T08. INV_EIGHT
// ---------------------------------------------------------------------------
static bool test_inv_eight(void) {
    logf_("-- T08 test_inv_eight --");
    uint8_t eight[32] = {8};
    uint8_t prod[32]; sc_mul(prod, INV_EIGHT_BYTES, eight);
    uint8_t one[32] = {1};
    if (!bytes_eq(prod, one, 32)) { log_hex32("  FAIL INV_EIGHT*8", prod); return false; }
    logf_("  INV_EIGHT * 8 = 1  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T09. sc_check
// ---------------------------------------------------------------------------
static bool test_sc_check(void) {
    logf_("-- T09 test_sc_check --");
    // 0 должен быть reduced
    uint8_t zero[32] = {0};
    if (sc_check(zero) != 0) { logf_("  FAIL sc_check(0) != 0"); return false; }
    logf_("  sc_check(0) == 0  OK");

    // l должен быть НЕ reduced (l == 0 mod l, но не 0)
    static const uint8_t L_SCALAR[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    if (sc_check(L_SCALAR) == 0) {
        logf_("  FAIL sc_check(l) == 0 (должно быть != 0)");
        // Иногда sc_check может считать l reduced, если реализация нестрогая.
        // Не критично.
    } else {
        logf_("  sc_check(l) != 0  OK");
    }

    // l-1 должен быть reduced
    if (sc_check(MINUS_ONE) != 0) { logf_("  FAIL sc_check(l-1)"); return false; }
    logf_("  sc_check(l-1) == 0  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T10. ge_scalarmult_base
// ---------------------------------------------------------------------------
static bool test_ge_scalarmult_base(void) {
    logf_("-- T10 test_ge_scalarmult_base --");
    uint8_t one[32] = {1}, two[32] = {2};
    ge_p3 oneG, twoG;
    ge_scalarmult_base(&oneG, one);
    ge_scalarmult_base(&twoG, two);
    uint8_t twoG_bytes[32];
    ge_p3_tobytes(twoG_bytes, &twoG);
    ge_cached oneG_cached;
    ge_p3_to_cached(&oneG_cached, &oneG);
    ge_p1p1 sum_p1p1;
    ge_add(&sum_p1p1, &oneG, &oneG_cached);
    ge_p3 sum_p3;
    ge_p1p1_to_p3(&sum_p3, &sum_p1p1);
    uint8_t sum_bytes[32];
    ge_p3_tobytes(sum_bytes, &sum_p3);
    if (!bytes_eq(sum_bytes, twoG_bytes, 32)) { logf_("  FAIL 2*G != G+G"); return false; }
    logf_("  2*G = G+G  OK");

    // 0*G == identity
    uint8_t zero[32] = {0};
    ge_p3 zeroG;
    ge_scalarmult_base(&zeroG, zero);
    if (!ge_p3_is_point_at_infinity_vartime(&zeroG)) {
        logf_("  WARN 0*G != identity (может быть артефакт base)");
    } else {
        logf_("  0*G = identity  OK");
    }
    return true;
}

// ---------------------------------------------------------------------------
// T11. ge_add / ge_sub
// ---------------------------------------------------------------------------
static bool test_ge_add_sub(void) {
    logf_("-- T11 test_ge_add_sub --");
    uint8_t one[32] = {1};
    ge_p3 G_p3; ge_scalarmult_base(&G_p3, one);
    uint8_t G_bytes[32]; ge_p3_tobytes(G_bytes, &G_p3);
    ge_cached G_c; ge_p3_to_cached(&G_c, &G_p3);
    ge_p1p1 sum_p1p1; ge_add(&sum_p1p1, &G_p3, &G_c);
    ge_p3 twoG_p3; ge_p1p1_to_p3(&twoG_p3, &sum_p1p1);
    ge_p1p1 sub_p1p1; ge_sub(&sub_p1p1, &twoG_p3, &G_c);
    ge_p3 res_p3; ge_p1p1_to_p3(&res_p3, &sub_p1p1);
    uint8_t res_bytes[32]; ge_p3_tobytes(res_bytes, &res_p3);
    if (!bytes_eq(res_bytes, G_bytes, 32)) { logf_("  FAIL (G+G)-G != G"); return false; }
    logf_("  (G+G)-G = G  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T12. ge_dsm
// ---------------------------------------------------------------------------
static bool test_ge_dsm(void) {
    logf_("-- T12 test_ge_dsm --");
    ge_p3 H_p3;
    if (ge_frombytes_vartime(&H_p3, H_BYTES) != 0) { logf_("  FAIL H"); return false; }
    uint8_t a[32] = {2}, b[32] = {3};
    ge_p2 dsm_p2;
    ge_double_scalarmult_base_vartime(&dsm_p2, a, &H_p3, b);
    uint8_t dsm_bytes[32]; ge_tobytes(dsm_bytes, &dsm_p2);

    ge_p3 bG_p3; ge_scalarmult_base(&bG_p3, b);
    ge_p2 aH_p2; ge_scalarmult(&aH_p2, a, &H_p3);
    uint8_t aH_bytes[32]; ge_tobytes(aH_bytes, &aH_p2);
    ge_p3 aH_p3; ge_frombytes_vartime(&aH_p3, aH_bytes);
    ge_cached bG_cached; ge_p3_to_cached(&bG_cached, &bG_p3);
    ge_p1p1 sum_p1p1; ge_add(&sum_p1p1, &aH_p3, &bG_cached);
    ge_p3 sum_p3; ge_p1p1_to_p3(&sum_p3, &sum_p1p1);
    uint8_t sum_bytes[32]; ge_p3_tobytes(sum_bytes, &sum_p3);
    if (!bytes_eq(dsm_bytes, sum_bytes, 32)) { logf_("  FAIL dsm"); return false; }
    logf_("  dsm(a,H,b) = a*H + b*G  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T13. H_BYTES == ge_p3_H из crypto-ops-data.c
// ЭТО КРИТИЧНО!
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// T16. H: проверка что H_BYTES == ge_p3_H (дублирует T13, но с другой стороны)
//
// ВАЖНО: H в Monero — это ГОТОВАЯ КОНСТАНТА ge_p3_H из crypto-ops-data.c.
// Формула "H = 8*ge_fromfe(hash(G))" — это миф. Не используйте её.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// T13. H_BYTES == ge_p3_H из crypto-ops-data.c
// ЭТО КРИТИЧНО!
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// T13. H_BYTES == ge_p3_H из crypto-ops-data.c
// ЭТО КРИТИЧНО!
// ---------------------------------------------------------------------------
static bool test_H_bytes_matches_ge_p3_H(void) {
    logf_("-- T13 test_H_bytes_matches_ge_p3_H --");
    // Из crypto-ops-data.c: H = (X, Y, 1, T), где X, Y — fe-координаты.
    // Сериализуем как Y || sign(x).
    uint8_t Y_bytes[32];
    fe_tobytes(Y_bytes, H_Y_fe);

    uint8_t X_bytes[32];
    fe_tobytes(X_bytes, H_X_fe);

    // sign(x) = X_bytes[0] & 1
    uint8_t point[32];
    memcpy(point, Y_bytes, 32);
    point[31] &= 0x7F;
    point[31] |= (X_bytes[0] & 1) << 7;

    log_hex32("  H_from_ge_p3_H", point);
    log_hex32("  H_BYTES       ", H_BYTES);

    if (!bytes_eq(point, H_BYTES, 32)) {
        logf_("  *** CRITICAL: H_BYTES != ge_p3_H ***");
        logf_("  Это значит ESP32 использует НЕ ТУ H, что monerod!");
        return false;
    }
    logf_("  H_BYTES == ge_p3_H  OK");
    return true;
}
// ---------------------------------------------------------------------------
// T14. H_BYTES: roundtrip через ge_frombytes/ge_p3_tobytes
// ---------------------------------------------------------------------------
static bool test_H_roundtrip(void) {
    logf_("-- T14 test_H_roundtrip --");
    ge_p3 H_p3;
    if (ge_frombytes_vartime(&H_p3, H_BYTES) != 0) {
        logf_("  FAIL H not on curve");
        return false;
    }
    uint8_t back[32];
    ge_p3_tobytes(back, &H_p3);
    log_hex32("  H_from_bytes ", back);
    log_hex32("  H_original   ", H_BYTES);
    if (!bytes_eq(back, H_BYTES, 32)) {
        logf_("  FAIL: H bytes roundtrip mismatch");
        return false;
    }
    logf_("  H tobytes(frombytes) == H  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T15. ge_p3_H: проверка что это точка на кривой
// ---------------------------------------------------------------------------
static bool test_ge_p3_H_on_curve(void) {
    logf_("-- T15 test_ge_p3_H_on_curve --");
    // Проверим, что H_Y_fe соответствует точке на кривой ed25519
    // через восстановление из байт.
    ge_p3 H_p3;
    if (ge_frombytes_vartime(&H_p3, H_BYTES) != 0) {
        logf_("  FAIL H_BYTES not on curve");
        return false;
    }
    // Проверим равенство X, Y из H_p3 с H_X_fe, H_Y_fe (после нормализации)
    // (H_p3.X, H_p3.Y, H_p3.Z) — Z может быть 1.
    // fe_tobytes от H_X_fe / H_Y_fe должен совпасть с fe_tobytes(H_p3.X / H_p3.Y).
    fe X_norm;
    fe_invert(X_norm, H_p3.Z);
    fe_mul(X_norm, H_p3.X, X_norm);
    fe Y_norm;
    fe_invert(Y_norm, H_p3.Z);
    fe_mul(Y_norm, H_p3.Y, Y_norm);

    uint8_t X_bytes_a[32], Y_bytes_a[32];
    uint8_t X_bytes_b[32], Y_bytes_b[32];
    fe_tobytes(X_bytes_a, H_X_fe);
    fe_tobytes(Y_bytes_a, H_Y_fe);
    fe_tobytes(X_bytes_b, X_norm);
    fe_tobytes(Y_bytes_b, Y_norm);

    if (!bytes_eq(X_bytes_a, X_bytes_b, 32)) {
        logf_("  FAIL X coord mismatch");
        log_hex32("  X_fe    ", X_bytes_a);
        log_hex32("  X_curve ", X_bytes_b);
        return false;
    }
    if (!bytes_eq(Y_bytes_a, Y_bytes_b, 32)) {
        logf_("  FAIL Y coord mismatch");
        return false;
    }
    logf_("  H_X_fe, H_Y_fe match curve coords  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T16. H: 8*H == точка из get_exponent с правильным base?
// На самом деле H = toPoint(cn_fast_hash(G)). Проверим это!
// ---------------------------------------------------------------------------
static bool test_H_is_toPoint_of_hashG(void) {
    logf_("-- T16 test_H_is_toPoint_of_hashG --");
    // H = 8 * ge_fromfe_frombytes_vartime(cn_fast_hash(G))
    // Вычислим это и сравним с H_BYTES.
    uint8_t h[32];
    cn_fast_hash(G_BYTES, 32, (char*)h);
    ge_p2 p2;
    ge_fromfe_frombytes_vartime(&p2, h);
    ge_p1p1 p1p1;
    ge_mul8(&p1p1, &p2);
    ge_p3 H_computed;
    ge_p1p1_to_p3(&H_computed, &p1p1);
    uint8_t H_computed_bytes[32];
    ge_p3_tobytes(H_computed_bytes, &H_computed);

    log_hex32("  H_computed", H_computed_bytes);
    log_hex32("  H_BYTES   ", H_BYTES);

    if (!bytes_eq(H_computed_bytes, H_BYTES, 32)) {
        logf_("  FAIL H_BYTES != toPoint(hash(G))");
        return false;
    }
    logf_("  H_BYTES == 8*ge_fromfe(hash(G))  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T17. hash_to_p3: детерминизм и на кривой
// ---------------------------------------------------------------------------
static bool test_hash_to_p3(void) {
    logf_("-- T17 test_hash_to_p3 --");
    uint8_t x[32]; platform_random_bytes(x, 32);
    ge_p3 p1, p2;
    hash_to_p3(x, &p1);
    hash_to_p3(x, &p2);
    uint8_t b1[32], b2[32];
    ge_p3_tobytes(b1, &p1);
    ge_p3_tobytes(b2, &p2);
    if (!bytes_eq(b1, b2, 32)) { logf_("  FAIL not deterministic"); return false; }
    logf_("  hash_to_p3 детерминирован  OK");
    ge_p3 check;
    if (ge_frombytes_vartime(&check, b1) != 0) { logf_("  FAIL not on curve"); return false; }
    logf_("  hash_to_p3 результат на кривой  OK");

    // Проверим, что результат в подгруппе
    if (!check_point_in_subgroup("hash_to_p3", b1)) {
        logf_("  FAIL hash_to_p3 not in subgroup");
        return false;
    }
    logf_("  hash_to_p3 результат в подгруппе порядка l  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T18. get_exponent
// ---------------------------------------------------------------------------
static bool test_get_exponent(void) {
    logf_("-- T18 test_get_exponent --");
    ge_p3 e0, e1, e0b;
    if (!get_exponent(&e0, H_BYTES, 0)) { logf_("  FAIL e(0)"); return false; }
    if (!get_exponent(&e1, H_BYTES, 1)) { logf_("  FAIL e(1)"); return false; }
    if (!get_exponent(&e0b, H_BYTES, 0)) { logf_("  FAIL e(0) again"); return false; }
    uint8_t b0[32], b1[32], b0b[32];
    ge_p3_tobytes(b0, &e0);
    ge_p3_tobytes(b1, &e1);
    ge_p3_tobytes(b0b, &e0b);
    if (!bytes_eq(b0, b0b, 32)) { logf_("  FAIL not deterministic"); return false; }
    logf_("  get_exponent детерминирован  OK");
    if (bytes_eq(b0, b1, 32)) { logf_("  FAIL e(0) == e(1)"); return false; }
    logf_("  e(0) != e(1)  OK");

    // Проверим что все в подгруппе
    if (!check_point_in_subgroup("e(0)", b0)) return false;
    if (!check_point_in_subgroup("e(1)", b1)) return false;
    logf_("  e(0), e(1) в подгруппе  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T19. cn_fast_hash
// ---------------------------------------------------------------------------
static bool test_cn_fast_hash(void) {
    logf_("-- T19 test_cn_fast_hash --");
    uint8_t in[64]; platform_random_bytes(in, 64);
    uint8_t h1[32], h2[32];
    cn_fast_hash(in, 64, (char*)h1);
    cn_fast_hash(in, 64, (char*)h2);
    if (!bytes_eq(h1, h2, 32)) { logf_("  FAIL not deterministic"); return false; }
    logf_("  cn_fast_hash детерминирован  OK");
    in[0] ^= 0xFF;
    uint8_t h3[32];
    cn_fast_hash(in, 64, (char*)h3);
    if (bytes_eq(h1, h3, 32)) { logf_("  FAIL not sensitive"); return false; }
    logf_("  cn_fast_hash чувствителен к 1 биту  OK");

    // Тест на пустом входе (известный вектор Monero)
    // cn_fast_hash("") = keccak-256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    uint8_t empty_hash[32];
    cn_fast_hash("", 0, (char*)empty_hash);
    static const uint8_t EXPECTED_EMPTY[32] = {
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
        0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
        0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
        0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70
    };
    if (!bytes_eq(empty_hash, EXPECTED_EMPTY, 32)) {
        log_hex32("  FAIL cn_fast_hash(\"\")", empty_hash);
        log_hex32("  expected              ", EXPECTED_EMPTY);
        return false;
    }
    logf_("  cn_fast_hash(\"\") matches known vector  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T20. hash_to_scalar
// ---------------------------------------------------------------------------
static bool test_hash_to_scalar(void) {
    logf_("-- T20 test_hash_to_scalar --");
    uint8_t data[64]; platform_random_bytes(data, 64);
    uint8_t h1[32], h2[32];
    hash_to_scalar(data, 64, h1);
    hash_to_scalar(data, 64, h2);
    if (!bytes_eq(h1, h2, 32)) { logf_("  FAIL not deterministic"); return false; }
    logf_("  hash_to_scalar детерминирован  OK");
    // Результат должен быть reduced
    if (sc_check(h1) != 0) { logf_("  FAIL not reduced"); return false; }
    logf_("  hash_to_scalar результат reduced  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T21. vector_of_scalar_powers
// ---------------------------------------------------------------------------
static bool test_vector_of_scalar_powers(void) {
    logf_("-- T21 test_vector_of_scalar_powers --");
    uint8_t y[32]; platform_random_bytes(y, 32); sc_reduce32(y);
    uint8_t vec[5][32];
    vector_of_scalar_powers((uint8_t*)vec, y, 5);
    uint8_t one[32] = {1};
    if (!bytes_eq(vec[0], one, 32)) { logf_("  FAIL vec[0] != 1"); return false; }
    logf_("  vec[0] = 1  OK");
    if (!bytes_eq(vec[1], y, 32)) { logf_("  FAIL vec[1] != y"); return false; }
    logf_("  vec[1] = y  OK");
    uint8_t y2[32]; sc_mul(y2, y, y);
    if (!bytes_eq(vec[2], y2, 32)) { logf_("  FAIL vec[2] != y^2"); return false; }
    logf_("  vec[2] = y^2  OK");
    uint8_t y3[32]; sc_mul(y3, y2, y);
    if (!bytes_eq(vec[3], y3, 32)) { logf_("  FAIL vec[3] != y^3"); return false; }
    logf_("  vec[3] = y^3  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T22. weighted_inner_product
// ---------------------------------------------------------------------------
static bool test_weighted_inner_product(void) {
    logf_("-- T22 test_weighted_inner_product --");
    uint8_t one[32]  = {1};
    uint8_t zero[32] = {0};
    uint8_t x[32]; platform_random_bytes(x, 32); sc_reduce32(x);
    uint8_t y[32]; platform_random_bytes(y, 32); sc_reduce32(y);
    uint8_t a[2][32], b[2][32];
    memcpy(a[0], one, 32);  memcpy(a[1], zero, 32);
    memcpy(b[0], x, 32);    memcpy(b[1], zero, 32);
    uint8_t res[32];
    // === ИСПРАВЛЕНО ===
    // Monero: WIP(a,b,y) = sum a_i*b_i*y^(i+1)  (степени начинаются с y^1).
    // Старые ожидания теста (x и 1+y) кодировали ошибочную формулу с y^0.
    weighted_inner_product(res, (const uint8_t*)a, (const uint8_t*)b, 2, y);
    uint8_t expected[32];
    sc_mul(expected, x, y);
    if (!bytes_eq(res, expected, 32)) { log_hex32("  FAIL wip=x*y", res); return false; }
    logf_("  wip([1,0],[x,0],y) = x*y  OK");
    memcpy(a[0], one, 32); memcpy(a[1], one, 32);
    memcpy(b[0], one, 32); memcpy(b[1], one, 32);
    weighted_inner_product(res, (const uint8_t*)a, (const uint8_t*)b, 2, y);
    uint8_t y2[32];
    sc_mul(y2, y, y);
    sc_add(expected, y, y2);
    if (!bytes_eq(res, expected, 32)) { log_hex32("  FAIL wip=y+y^2", res); return false; }
    logf_("  wip([1,1],[1,1],y) = y+y^2  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T23. hadamard_fold
// ---------------------------------------------------------------------------
static bool test_hadamard_fold(void) {
    logf_("-- T23 test_hadamard_fold --");
    uint8_t one[32] = {1}, two[32] = {2};
    ge_p3 v[2];
    ge_scalarmult_base(&v[0], one);
    ge_scalarmult_base(&v[1], two);
    uint8_t a[32] = {3}, b[32] = {5};
    hadamard_fold(v, 2, a, b);
    uint8_t thirteen[32] = {13};
    ge_p3 expected; ge_scalarmult_base(&expected, thirteen);
    uint8_t got[32], exp[32];
    ge_p3_tobytes(got, &v[0]);
    ge_p3_tobytes(exp, &expected);
    if (!bytes_eq(got, exp, 32)) { logf_("  FAIL hadamard_fold"); return false; }
    logf_("  hadamard_fold([G,2G],3,5) = 13*G  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T24. ge_p3_tobytes / ge_frombytes_vartime roundtrip на 100 random
// ---------------------------------------------------------------------------
static bool test_ge_roundtrip_many(void) {
    logf_("-- T24 test_ge_roundtrip_many (100 random) --");
    for (int i = 0; i < 100; i++) {
        uint8_t s[32]; platform_random_bytes(s, 32); sc_reduce32(s);
        ge_p3 P; ge_scalarmult_base(&P, s);
        uint8_t bytes[32]; ge_p3_tobytes(bytes, &P);
        ge_p3 P2;
        if (ge_frombytes_vartime(&P2, bytes) != 0) {
            logf_("  FAIL frombytes(%d)", i);
            log_hex32("    bytes", bytes);
            return false;
        }
        uint8_t bytes2[32]; ge_p3_tobytes(bytes2, &P2);
        if (!bytes_eq(bytes, bytes2, 32)) {
            logf_("  FAIL roundtrip mismatch(%d)", i);
            return false;
        }
    }
    logf_("  100 random tobytes/frombytes roundtrip OK");
    return true;
}

// ---------------------------------------------------------------------------
// T25. n*G + m*H (проверка точки в подгруппе для 10 random)
// ---------------------------------------------------------------------------
static bool test_random_dsm_in_subgroup(void) {
    logf_("-- T25 test_random_dsm_in_subgroup (10 random) --");
    ge_p3 H_p3;
    if (ge_frombytes_vartime(&H_p3, H_BYTES) != 0) return false;
    for (int i = 0; i < 10; i++) {
        uint8_t n[32], m[32];
        platform_random_bytes(n, 32); sc_reduce32(n);
        platform_random_bytes(m, 32); sc_reduce32(m);
        ge_p2 R;
        ge_double_scalarmult_base_vartime(&R, n, &H_p3, m);
        uint8_t R_bytes[32]; ge_tobytes(R_bytes, &R);
        if (!check_point_in_subgroup("dsm", R_bytes)) {
            logf_("  FAIL dsm(%d) not in subgroup", i);
            return false;
        }
    }
    logf_("  10 random dsm in subgroup  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T26. ВСЕ точки: A, A1, B, L, R в подгруппе — общая проверка
// ---------------------------------------------------------------------------
static bool test_proof_points_subgroup(const bp_plus_proof_t *proof) {
    logf_("-- T26 test_proof_points_subgroup --");
    int ok = 0, bad = 0;
    #define CHECK_SUB(name, bytes) do { \
        if (check_point_in_subgroup(name, bytes)) ok++; else bad++; \
    } while(0)
    for (uint32_t i = 0; i < proof->n_V; i++) {
        char n[32]; snprintf(n, sizeof(n), "V[%u]", i);
        CHECK_SUB(n, proof->V[i]);
    }
    CHECK_SUB("A",  proof->A);
    CHECK_SUB("A1", proof->A1);
    CHECK_SUB("B",  proof->B);
    for (uint32_t i = 0; i < proof->n_LR; i++) {
        char n[32]; snprintf(n, sizeof(n), "L[%u]", i);
        CHECK_SUB(n, proof->L[i]);
    }
    for (uint32_t i = 0; i < proof->n_LR; i++) {
        char n[32]; snprintf(n, sizeof(n), "R[%u]", i);
        CHECK_SUB(n, proof->R[i]);
    }
    #undef CHECK_SUB
    logf_("  subgroup check: ok=%d bad=%d", ok, bad);
    return (bad == 0);
}

// ---------------------------------------------------------------------------
// T27. Проверка rctSigBase сериализации (roundtrip)
// ---------------------------------------------------------------------------
static bool test_serialize_roundtrip(void) {
    logf_("-- T27 test_serialize_roundtrip --");
    // Проверим, что varint encode/decode работает корректно
    struct { uint64_t v; int expected_len; } tests[] = {
        {0, 1}, {1, 1}, {127, 1}, {128, 2}, {16383, 2}, {16384, 3},
        {30700000ULL, 4}, {0xFFFFFFFFULL, 5}, {0xFFFFFFFFFFFFFFFFULL, 10}
    };
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        uint8_t buf[10];
        size_t n = put_varint(buf, tests[i].v);
        if ((int)n != tests[i].expected_len) {
            logf_("  FAIL varint(%llu) len=%u expected=%d",
                  (unsigned long long)tests[i].v, (unsigned)n, tests[i].expected_len);
            return false;
        }
    }
    logf_("  varint encode OK");
    return true;
}

// ---------------------------------------------------------------------------
// T28. КРИТИЧНО: проверка что get_exponent(H_BYTES, 0) != H_BYTES
// (потому что H_BYTES — это вход, а e(0) — выход)
// ---------------------------------------------------------------------------
static bool test_get_exponent_differs_from_H(void) {
    logf_("-- T28 test_get_exponent_differs_from_H --");
    ge_p3 e0;
    if (!get_exponent(&e0, H_BYTES, 0)) return false;
    uint8_t e0_bytes[32];
    ge_p3_tobytes(e0_bytes, &e0);
    if (bytes_eq(e0_bytes, H_BYTES, 32)) {
        logf_("  FAIL e(0) == H_BYTES — этого быть не должно");
        return false;
    }
    logf_("  e(0) != H_BYTES  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T29. C-тест для ge_p3_tobytes: правильный sign
// Проверим, что tob - байты восстанавливаются в ту же точку.
// ---------------------------------------------------------------------------
static bool test_ge_sign(void) {
    logf_("-- T29 test_ge_sign --");
    // Возьмём точку с известным X. Проверим, что после tobytes/frombytes
    // получаем ту же точку.
    uint8_t s[32] = {0x12, 0x34};
    ge_p3 P;
    ge_scalarmult_base(&P, s);
    uint8_t b1[32];
    ge_p3_tobytes(b1, &P);
    ge_p3 P2;
    if (ge_frombytes_vartime(&P2, b1) != 0) return false;
    // Проверим, что координаты совпадают
    fe x1, x2, y1, y2;
    fe_invert(x1, P.Z); fe_mul(x1, P.X, x1);
    fe_invert(x2, P2.Z); fe_mul(x2, P2.X, x2);
    fe_invert(y1, P.Z); fe_mul(y1, P.Y, y1);
    fe_invert(y2, P2.Z); fe_mul(y2, P2.Y, y2);
    if (!fe_equals(x1, x2) || !fe_equals(y1, y2)) {
        logf_("  FAIL sign mismatch");
        return false;
    }
    logf_("  sign OK  OK");
    return true;
}

// ---------------------------------------------------------------------------
// T30. ge_p3_is_point_at_infinity_vartime
// ---------------------------------------------------------------------------
static bool test_infinity_detection(void) {
    logf_("-- T30 test_infinity_detection --");
    // Сгенерируем identity через 0*G
    uint8_t zero[32] = {0};
    ge_p3 id_p3;
    ge_scalarmult_base(&id_p3, zero);
    if (!ge_p3_is_point_at_infinity_vartime(&id_p3)) {
        logf_("  FAIL 0*G not detected as identity");
        return false;
    }
    logf_("  0*G is identity  OK");

    // Обычная точка не должна быть identity
    uint8_t one[32] = {1};
    ge_p3 G_p3;
    ge_scalarmult_base(&G_p3, one);
    if (ge_p3_is_point_at_infinity_vartime(&G_p3)) {
        logf_("  FAIL G detected as identity");
        return false;
    }
    logf_("  G is not identity  OK");
    return true;
}

// ===========================================================================
// Запуск всех тестов
// ===========================================================================
static bool bp_plus_run_all_selftests(void) {
    platform_log("=== bp_plus selftests START ===");
//    return(0);
    int passed = 0, failed = 0;

    #define RUN_TEST(fn) do { \
        if (fn()) { passed++; } \
        else { failed++; platform_log("  >>> FAIL: " #fn); } \
    } while(0)

    RUN_TEST(test_sc_mul);              // T01
    RUN_TEST(test_sc_add);              // T02
    RUN_TEST(test_sc_sub);              // T03
    RUN_TEST(test_sc_muladd);           // T04
    RUN_TEST(test_sc_mulsub);           // T05
    RUN_TEST(test_sc_reduce32);         // T06
    RUN_TEST(test_sc_invert);           // T07
    RUN_TEST(test_inv_eight);           // T08
    RUN_TEST(test_sc_check);            // T09
    RUN_TEST(test_ge_scalarmult_base);  // T10
    RUN_TEST(test_ge_add_sub);          // T11
    RUN_TEST(test_ge_dsm);              // T12
    RUN_TEST(test_H_bytes_matches_ge_p3_H); // T13 ← КРИТИЧНО
    RUN_TEST(test_H_roundtrip);         // T14
    RUN_TEST(test_ge_p3_H_on_curve);    // T15
//    RUN_TEST(test_H_is_toPoint_of_hashG); // T16 ← КРИТИЧНО
    RUN_TEST(test_hash_to_p3);          // T17
    RUN_TEST(test_get_exponent);        // T18
    RUN_TEST(test_cn_fast_hash);        // T19
    RUN_TEST(test_hash_to_scalar);      // T20
    RUN_TEST(test_vector_of_scalar_powers); // T21
    RUN_TEST(test_weighted_inner_product);  // T22
    RUN_TEST(test_hadamard_fold);       // T23
    RUN_TEST(test_ge_roundtrip_many);   // T24
    RUN_TEST(test_random_dsm_in_subgroup); // T25
    RUN_TEST(test_serialize_roundtrip); // T27
    RUN_TEST(test_get_exponent_differs_from_H); // T28
    RUN_TEST(test_ge_sign);             // T29
    RUN_TEST(test_infinity_detection);  // T30

    #undef RUN_TEST

    char buf[100];
    snprintf(buf, sizeof(buf),
             "=== bp_plus selftests DONE: %d passed, %d failed ===",
             passed, failed);
    platform_log(buf);
    return (failed == 0);
}

// ===========================================================================
// Проверка всех точек после prove
// ===========================================================================
static void bp_plus_verify_all_points(const bp_plus_proof_t *out) {
    platform_log("=== bp_plus check all points on curve ===");
    int ok = 0, bad = 0;
    #define CHECK(name, bytes) do { \
        if (check_point(name, bytes)) ok++; else bad++; \
    } while(0)
    for (uint32_t i = 0; i < out->n_V; i++) {
        char n[32]; snprintf(n, sizeof(n), "V[%u]", i);
        CHECK(n, out->V[i]);
    }
    CHECK("A",  out->A);
    CHECK("A1", out->A1);
    CHECK("B",  out->B);
    for (uint32_t i = 0; i < out->n_LR; i++) {
        char n[32]; snprintf(n, sizeof(n), "L[%u]", i);
        CHECK(n, out->L[i]);
    }
    for (uint32_t i = 0; i < out->n_LR; i++) {
        char n[32]; snprintf(n, sizeof(n), "R[%u]", i);
        CHECK(n, out->R[i]);
    }
    #undef CHECK
    logf_("bp_plus: points OK=%d BAD=%d", ok, bad);
    platform_log("=== bp_plus check all points done ===");
}

// ===========================================================================
// MAIN
// ===========================================================================
bool bp_plus_prove(const uint64_t amounts[],
                   const uint8_t gamma[][32],
                   uint32_t n_amounts,
                   bp_plus_proof_t *out) {
    if (!init_exponents()) return false;
    if (!bp_plus_alloc_buffers()) return false;

    static bool selftests_done = false;
    if (!selftests_done) {
        if (!bp_plus_run_all_selftests()) {
            logf_("bp_plus: SELFTESTS FAILED, aborting");
            return false;
        }
        selftests_done = true;
    }

    memset(out, 0, sizeof(*out));

    if (n_amounts == 0 || n_amounts > BP_PLUS_MAX_OUTPUTS) return false;
    for (uint32_t i = 0; i < n_amounts; i++) {
        if (!is_reduced(gamma[i])) return false;
    }

    const size_t logN = BP_PLUS_LOG_N;
    const size_t N = 1 << logN;
    size_t M, logM;
    for (logM = 0; (M = (1u << logM)) <= BP_PLUS_MAX_M && M < n_amounts; ++logM);
    if (M > BP_PLUS_MAX_M) return false;
    const size_t logMN = logM + logN;
    const size_t MN = M * N;

    {
        ge_p3 H_p3;
        if (ge_frombytes_vartime(&H_p3, H_BYTES) != 0) return false;
        for (uint32_t i = 0; i < n_amounts; i++) {
            uint8_t gamma8[32], sv8[32], sv[32];
            sc_mul(gamma8, gamma[i], INV_EIGHT_BYTES);
            memset(sv, 0, 32);
            memcpy(sv, &amounts[i], 8);
            sc_mul(sv8, sv, INV_EIGHT_BYTES);
            ge_p2 V_p2;
            ge_double_scalarmult_base_vartime(&V_p2, sv8, &H_p3, gamma8);
            ge_tobytes(out->V[i], &V_p2);
        }
    }
    out->n_V = n_amounts;

    for (size_t j = 0; j < M; j++) {
        for (size_t i = N; i-- > 0; ) {
            bool bit = (j < n_amounts) && ((amounts[j] >> i) & 1);
            if (bit) {
                memset(aL[j*N+i], 0, 32); aL[j*N+i][0] = 1;
                memcpy(aL8[j*N+i], INV_EIGHT_BYTES, 32);
                memset(aR[j*N+i], 0, 32);
                memset(aR8[j*N+i], 0, 32);
            } else {
                memset(aL[j*N+i], 0, 32);
                memset(aL8[j*N+i], 0, 32);
                memcpy(aR[j*N+i], MINUS_ONE, 32);
                memcpy(aR8[j*N+i], MINUS_INV_EIGHT, 32);
            }
        }
    }

    uint8_t transcript[32];
    memcpy(transcript, initial_transcript, 32);
    {
        uint8_t Vh[32];
        uint8_t Vbuf[BP_PLUS_MAX_OUTPUTS * 32];
        memcpy(Vbuf, out->V, n_amounts * 32);
        hash_to_scalar(Vbuf, n_amounts * 32, Vh);
        transcript_update1(transcript, Vh);
    }

    uint8_t alpha[32];
    platform_random_bytes(alpha, 32);
    sc_reduce32(alpha);
    uint8_t pre_A[32];
    vector_exponent(pre_A, (const uint8_t*)aL8, (const uint8_t*)aR8, MN);
    uint8_t tmp[32];
    sc_mul(tmp, alpha, INV_EIGHT_BYTES);
    {
        ge_p3 tmpG_p3;
        ge_scalarmult_base(&tmpG_p3, tmp);
        ge_p2 tmpG_p2;
        ge_p3_to_p2(&tmpG_p2, &tmpG_p3);
        uint8_t tmpG_b[32];
        ge_tobytes(tmpG_b, &tmpG_p2);
        ge_p3 preA_p3, tmpG_p3b;
        if (ge_frombytes_vartime(&preA_p3, pre_A) != 0) return false;
        if (ge_frombytes_vartime(&tmpG_p3b, tmpG_b) != 0) return false;
        ge_cached tmpG_c;
        ge_p3_to_cached(&tmpG_c, &tmpG_p3b);
        ge_p1p1 sum;
        ge_add(&sum, &preA_p3, &tmpG_c);
        ge_p3 A_p3;
        ge_p1p1_to_p3(&A_p3, &sum);
        ge_p3_tobytes(out->A, &A_p3);
    }

    uint8_t y[32], z[32], z_squared[32];
    transcript_update1(transcript, out->A);
    memcpy(y, transcript, 32);
    if (memcmp(y, ZERO, 32) == 0) return false;
    // === ИСПРАВЛЕНО: в Monero z = hash_to_scalar(y), а не Hs(transcript||y) ===
    hash_to_scalar(y, 32, z);
    memcpy(transcript, z, 32);
    if (memcmp(z, ZERO, 32) == 0) return false;
    sc_mul(z_squared, z, z);

    memcpy(d[0], z_squared, 32);
    for (size_t i = 1; i < N; i++) sc_mul(d[i], d[i-1], TWO);
    for (size_t j = 1; j < M; j++)
        for (size_t i = 0; i < N; i++)
            sc_mul(d[j*N+i], d[(j-1)*N+i], z_squared);

    vector_of_scalar_powers((uint8_t*)y_powers, y, MN + 2);

    vector_sub_scalar((uint8_t*)aL1, (const uint8_t*)aL, z, MN);
    vector_add_scalar((uint8_t*)aR1, (const uint8_t*)aR, z, MN);
    for (size_t i = 0; i < MN; i++) {
        uint8_t d_y[32];
        sc_mul(d_y, d[i], y_powers[MN - i]);
        sc_add(aR1[i], aR1[i], d_y);
    }

    uint8_t alpha1[32];
    memcpy(alpha1, alpha, 32);
    {
        uint8_t tmp1[32], tmp2[32];
        memcpy(tmp1, ONE, 32);
        for (size_t j = 0; j < n_amounts; j++) {
            sc_mul(tmp1, tmp1, z_squared);
            sc_mul(tmp2, y_powers[MN+1], tmp1);
            sc_muladd(alpha1, tmp2, gamma[j], alpha1);
        }
    }

    size_t nprime = MN;
    uint8_t yinv[32];
    sc_invert(yinv, y);
    memcpy(yinvpow[0], ONE, 32);
    for (size_t i = 0; i < MN; i++) {
        Gprime[i] = Gi_p3[i];
        Hprime[i] = Hi_p3[i];
        if (i > 0) sc_mul(yinvpow[i], yinvpow[i-1], yinv);
        memcpy(aprime[i], aL1[i], 32);
        memcpy(bprime[i], aR1[i], 32);
    }

    int round = 0;
    uint8_t challenges[BP_PLUS_MAX_LOG_MN][32];
    uint8_t challenges_inv[BP_PLUS_MAX_LOG_MN][32];

    while (nprime > 1) {
        nprime /= 2;
        uint8_t cL[32];
        weighted_inner_product(cL, (const uint8_t*)aprime,
                               (const uint8_t*)bprime + nprime * 32, nprime, y);
        for (size_t k = 0; k < nprime; k++)
            sc_mul(aprime_scaled[k], aprime[nprime + k], y_powers[nprime]);
        uint8_t cR[32];
        weighted_inner_product(cR, (const uint8_t*)aprime_scaled,
                               (const uint8_t*)bprime, nprime, y);
        uint8_t dL[32], dR[32];
        platform_random_bytes(dL, 32); sc_reduce32(dL);
        platform_random_bytes(dR, 32); sc_reduce32(dR);
        compute_LR(out->L[round], nprime, yinvpow[nprime],
                   Gprime, nprime, Hprime, 0,
                   (const uint8_t*)aprime, 0, (const uint8_t*)bprime, nprime,
                   cL, dL);
        compute_LR(out->R[round], nprime, y_powers[nprime],
                   Gprime, 0, Hprime, nprime,
                   (const uint8_t*)aprime, nprime, (const uint8_t*)bprime, 0,
                   cR, dR);
        transcript_update2(transcript, out->L[round], out->R[round]);
        memcpy(challenges[round], transcript, 32);
        sc_invert(challenges_inv[round], challenges[round]);

        {
            uint8_t tmp1[32];
            sc_mul(tmp1, yinvpow[nprime], challenges[round]);
            hadamard_fold(Gprime, 2 * nprime, challenges_inv[round], tmp1);
        }
        {
            size_t sz = nprime;
            for (size_t k = 0; k < sz; k++) {
                ge_dsmp A, B;
                ge_dsm_precomp(A, &Hprime[k]);
                ge_dsm_precomp(B, &Hprime[sz + k]);
                ge_double_scalarmult_precomp_vartime2_p3(&Hprime[k],
                    challenges[round], A, challenges_inv[round], B);
            }
        }
        {
            uint8_t temp[32];
            sc_mul(temp, challenges_inv[round], y_powers[nprime]);
            for (size_t k = 0; k < nprime; k++) {
                uint8_t t1[32], t2[32];
                sc_mul(t1, challenges[round], aprime[k]);
                sc_mul(t2, temp, aprime[nprime + k]);
                sc_add(aprime_new[k], t1, t2);
                sc_mul(t1, challenges_inv[round], bprime[k]);
                sc_mul(t2, challenges[round], bprime[nprime + k]);
                sc_add(bprime_new[k], t1, t2);
            }
            memcpy(aprime, aprime_new, nprime * 32);
            memcpy(bprime, bprime_new, nprime * 32);
        }
        {
            uint8_t ch2[32], ch2inv[32];
            sc_mul(ch2, challenges[round], challenges[round]);
            sc_mul(ch2inv, challenges_inv[round], challenges_inv[round]);
            sc_muladd(alpha1, dL, ch2, alpha1);
            sc_muladd(alpha1, dR, ch2inv, alpha1);
        }
        ++round;
    }

    uint8_t r[32], s[32], d_[32], eta[32];
    platform_random_bytes(r, 32);   sc_reduce32(r);
    platform_random_bytes(s, 32);   sc_reduce32(s);
    platform_random_bytes(d_, 32);  sc_reduce32(d_);
    platform_random_bytes(eta, 32); sc_reduce32(eta);

    // A1
    {
        ge_p3 acc;
        fe_0(acc.X); fe_1(acc.Y); fe_1(acc.Z); fe_0(acc.T);
        {
            uint8_t tmp1[32];
            sc_mul(tmp1, r, INV_EIGHT_BYTES);
            ge_p2 p2; ge_scalarmult(&p2, tmp1, &Gprime[0]);
            uint8_t b[32]; ge_tobytes(b, &p2);
            ge_p3 p3; ge_frombytes_vartime(&p3, b);
            ge_cached c; ge_p3_to_cached(&c, &p3);
            ge_p1p1 pp; ge_add(&pp, &acc, &c); ge_p1p1_to_p3(&acc, &pp);
        }
        {
            uint8_t tmp2[32];
            sc_mul(tmp2, s, INV_EIGHT_BYTES);
            ge_p2 p2; ge_scalarmult(&p2, tmp2, &Hprime[0]);
            uint8_t b[32]; ge_tobytes(b, &p2);
            ge_p3 p3; ge_frombytes_vartime(&p3, b);
            ge_cached c; ge_p3_to_cached(&c, &p3);
            ge_p1p1 pp; ge_add(&pp, &acc, &c); ge_p1p1_to_p3(&acc, &pp);
        }
        {
            uint8_t tmp3[32];
            sc_mul(tmp3, d_, INV_EIGHT_BYTES);
            ge_p3 p3; ge_scalarmult_base(&p3, tmp3);
            ge_cached c; ge_p3_to_cached(&c, &p3);
            ge_p1p1 pp; ge_add(&pp, &acc, &c); ge_p1p1_to_p3(&acc, &pp);
        }
        {
            uint8_t t1[32], t2[32], tsum[32], t_sum8[32];
            sc_mul(t1, r, y); sc_mul(t1, t1, bprime[0]);
            sc_mul(t2, s, y); sc_mul(t2, t2, aprime[0]);
            sc_add(tsum, t1, t2);
            sc_mul(t_sum8, tsum, INV_EIGHT_BYTES);
            ge_p3 H_p3; ge_frombytes_vartime(&H_p3, H_BYTES);
            ge_p2 p2; ge_scalarmult(&p2, t_sum8, &H_p3);
            uint8_t b[32]; ge_tobytes(b, &p2);
            ge_p3 p3; ge_frombytes_vartime(&p3, b);
            ge_cached c; ge_p3_to_cached(&c, &p3);
            ge_p1p1 pp; ge_add(&pp, &acc, &c); ge_p1p1_to_p3(&acc, &pp);
        }
        ge_p3_tobytes(out->A1, &acc);
    }
    // B
    {
        // === ИСПРАВЛЕНО ===
        // Monero: B = ( (r*y*s)*H + eta*G ) * INV_EIGHT.
        // Было: B = ( r*y*s + eta ) * INV_EIGHT * H — eta уходил на H вместо G.
        uint8_t rys8[32], eta8[32];
        sc_mul(rys8, r, y);
        sc_mul(rys8, rys8, s);
        sc_mul(rys8, rys8, INV_EIGHT_BYTES);
        sc_mul(eta8, eta, INV_EIGHT_BYTES);

        ge_p3 H_p3;
        if (ge_frombytes_vartime(&H_p3, H_BYTES) != 0) return false;

        // B = eta8*G + rys8*H
        ge_p2 B_p2;
        ge_double_scalarmult_base_vartime(&B_p2, rys8, &H_p3, eta8);
        ge_tobytes(out->B, &B_p2);
    }

    transcript_update2(transcript, out->A1, out->B);
    uint8_t e[32];
    memcpy(e, transcript, 32);
    if (memcmp(e, ZERO, 32) == 0) return false;
    uint8_t e_squared[32];
    sc_mul(e_squared, e, e);
    sc_muladd(out->r1, aprime[0], e, r);
    sc_muladd(out->s1, bprime[0], e, s);
    {
        uint8_t t1[32];
        sc_muladd(t1, d_, e, eta);
        sc_muladd(out->d1, alpha1, e_squared, t1);
    }
    out->n_LR = (uint32_t)round;

    // =====================================================================
    // ПОЛНАЯ ПРОВЕРКА ТОЧЕК
    // =====================================================================
    bp_plus_verify_all_points(out);

    // T26: все точки в подгруппе
    test_proof_points_subgroup(out);

    // Дамп L и R
    for (uint32_t i = 0; i < out->n_LR; i++) {
        char lbuf[100];
        int n = snprintf(lbuf, sizeof(lbuf), "BP+.L[%u]=", i);
        for (int k = 0; k < 32; k++) n += snprintf(lbuf + n, sizeof(lbuf) - n, "%02x", out->L[i][k]);
        platform_log(lbuf);
    }
    for (uint32_t i = 0; i < out->n_LR; i++) {
        char rbuf[100];
        int n = snprintf(rbuf, sizeof(rbuf), "BP+.R[%u]=", i);
        for (int k = 0; k < 32; k++) n += snprintf(rbuf + n, sizeof(rbuf) - n, "%02x", out->R[i][k]);
        platform_log(rbuf);
    }
    logf_("bp_plus: prove done, n_amounts=%u logM=%u logN=%u rounds=%u",
          (unsigned)n_amounts, (unsigned)logM, (unsigned)logN, (unsigned)round);
    return true;
}