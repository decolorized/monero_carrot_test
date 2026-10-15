// clsag.c
//
// Порт rctSigs.cpp::CLSAG_Gen + proveRctCLSAGSimple на C.
//
// Все тяжёлые буферы вынесены в static (.bss), чтобы не переполнять стек.
//
// Ключевые моменты (сверено с rctSigs.cpp и device_default.cpp):
//   1. H = Hp(P[l]) = hash_to_p3(P[l]) — ВАЖНО: НЕ фиксированная H_BYTES!
//      Это хеш от публичного ключа реального выхода.
//   2. clsag_prepare: a = random, aG = a*G, aH = a*H, I = p*H, D = z*H (несжатые).
//   3. sig.D = D * INV_EIGHT (сжатый в 1/8).
//   4. mu_P = Hs("CLSAG_agg_0" || P[0..n-1] || C_nonzero[0..n-1] || I || D || C_offset)
//      mu_C = Hs("CLSAG_agg_1" || P[0..n-1] || C_nonzero[0..n-1] || I || D || C_offset)
//      ВАЖНО: используется C_nonzero, не C!
//   5. c = Hs("CLSAG_round" || P[0..n-1] || C_nonzero[0..n-1] || C_offset || message || aG || aH)
//   6. C[i] = C_nonzero[i] - C_offset (только для вычисления L).
//   7. L = s[i]*G + c*mu_P*P[i] + c*mu_C*C[i]
//      R = s[i]*Hp(P[i]) + c*mu_P*I + c*mu_C*D_unc
//   8. s[l] = -c * (mu_P*p + mu_C*z) + a
//   9. c1 копируется ПОСЛЕ обновления c, когда i == 0
//      (Monero CLSAG_Gen: c = c_new; i = (i+1)%n; if (i==0) c1 = c).

#include "clsag.h"
#include "crypto-ops.h"
#include "hash-ops.h"
#include "keccak.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

extern void platform_log(const char *msg);
extern void platform_random_bytes(uint8_t *buf, size_t n);

// ===========================================================================
// Константы
// ===========================================================================

static const uint8_t INV_EIGHT_BYTES[32] = {
    0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61,
    0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06
};

// Домены хеширования
static const char HASH_KEY_CLSAG_AGG_0[] = "CLSAG_agg_0";
static const char HASH_KEY_CLSAG_AGG_1[] = "CLSAG_agg_1";
static const char HASH_KEY_CLSAG_ROUND[] = "CLSAG_round";

// ===========================================================================
// Утилиты
// ===========================================================================

static void logf_(const char *fmt, ...) {
    char buf[200];
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

// Hs(data) = sc_reduce32(cn_fast_hash(data))
static void hash_to_scalar(const void *data, size_t len, uint8_t out[32]) {
    cn_fast_hash(data, len, (char*)out);
    sc_reduce32(out);
}

// Hp(P) = 8 * ge_fromfe_frombytes_vartime(cn_fast_hash(P))
static void hash_to_p3(const uint8_t P[32], ge_p3 *out) {
    uint8_t h[32];
    cn_fast_hash(P, 32, (char*)h);
    ge_p2 p2;
    ge_fromfe_frombytes_vartime(&p2, h);
    ge_p1p1 p1p1;
    ge_mul8(&p1p1, &p2);
    ge_p1p1_to_p3(out, &p1p1);
}

// ===========================================================================
// === ДОБАВЛЕНО: хеджированные детерминированные нонсы ===
//
// Нонс выводится из секрета и ПОЛНОГО контекста подписи, плюс 32 байта из ГСЧ.
// Безопасно, если ГСЧ хорош, и безопасно, если ГСЧ выдаёт константу — проиграть
// нельзя. Это стандартная конструкция (hedged EdDSA / XEdDSA).
//
// Почему в контекст обязано входить ВСЁ кольцо: хост присылает кольцо и индекс
// реального выхода. Злонамеренный хост может попросить подписать один и тот же
// выход дважды с разными подставными кольцами. Если a зависит только от
// (p, message), то a повторится, а c будет другим — и p достаётся из двух
// линейных уравнений. Привязка кольца тут не опция.
//
// Каждое поле длиной с префиксом: без этого (P[0]||P[1]) и другое разбиение
// той же строки дают одинаковый хеш — ровно та коллизия, которую ищет атакующий.
// ===========================================================================
typedef struct { KECCAK_CTX k; } nonce_ctx;

static void nonce_add(nonce_ctx *c, const void *d, size_t n) {
    uint8_t len_le[4] = { (uint8_t)n, (uint8_t)(n >> 8),
                          (uint8_t)(n >> 16), (uint8_t)(n >> 24) };
    keccak_update(&c->k, len_le, 4);
    keccak_update(&c->k, (const uint8_t *)d, n);
}

static void nonce_begin(nonce_ctx *c, const char *domain, const uint8_t secret[32]) {
    keccak_init(&c->k);
    nonce_add(c, domain, strlen(domain) + 1);
    nonce_add(c, secret, 32);
    uint8_t hedge[32];
    platform_random_bytes(hedge, 32);
    nonce_add(c, hedge, 32);
    memset(hedge, 0, 32);
}

static void nonce_finish(nonce_ctx *c, uint8_t out[32]) {
    uint8_t h[32];
    keccak_finish(&c->k, h);
    memcpy(out, h, 32);
    sc_reduce32(out);
    memset(h, 0, 32);
    memset(c, 0, sizeof(*c));
}

// Полный контекст подписи: всё, что влияет на challenge c.
static void clsag_nonce_seed(uint8_t seed[32],
                             const uint8_t p[32], const uint8_t z[32],
                             const uint8_t message[32], const uint8_t H[32],
                             const uint8_t C_offset[32],
                             const uint8_t P[][32], const uint8_t C_nonzero[][32],
                             uint32_t l, uint32_t n)
{
    nonce_ctx nc;
    nonce_begin(&nc, "XMR_CLSAG_nonce_v1", p);
    nonce_add(&nc, z, 32);
    nonce_add(&nc, message, 32);
    nonce_add(&nc, H, 32);            // Hp(P[l]) — I ещё не посчитан на этом шаге
    nonce_add(&nc, C_offset, 32);
    uint8_t idx[8] = { (uint8_t)l, (uint8_t)(l >> 8), (uint8_t)(l >> 16), (uint8_t)(l >> 24),
                       (uint8_t)n, (uint8_t)(n >> 8), (uint8_t)(n >> 16), (uint8_t)(n >> 24) };
    nonce_add(&nc, idx, 8);
    for (uint32_t i = 0; i < n; i++) nonce_add(&nc, P[i], 32);
    for (uint32_t i = 0; i < n; i++) nonce_add(&nc, C_nonzero[i], 32);
    nonce_finish(&nc, seed);
}

// a и подставные s[i] выводятся из одного seed; для s[i] в хеш идёт индекс,
// иначе все подставные совпадут.
static void clsag_nonce_derive(uint8_t out[32], const uint8_t seed[32],
                               const char *tag, uint32_t index)
{
    uint8_t buf[32 + 8 + 4];
    size_t pos = 0;
    memcpy(buf + pos, seed, 32); pos += 32;
    size_t tl = strlen(tag);
    memcpy(buf + pos, tag, tl); pos += tl;
    buf[pos++] = (uint8_t)index;       buf[pos++] = (uint8_t)(index >> 8);
    buf[pos++] = (uint8_t)(index >> 16); buf[pos++] = (uint8_t)(index >> 24);
    cn_fast_hash(buf, pos, (char *)out);
    sc_reduce32(out);
    memset(buf, 0, sizeof(buf));
}

// ===========================================================================
// clsag_prepare
// ===========================================================================
static void clsag_prepare(const uint8_t p[32], const uint8_t z[32],
                          uint8_t I[32], uint8_t D[32],
                          const uint8_t H[32],
                          const uint8_t a[32], uint8_t aG[32], uint8_t aH[32])
{
    // a приходит готовым: выводится детерминированно из контекста подписи
    // (см. clsag_nonce_seed), а не берётся из ГСЧ напрямую.
    ge_p3 aG_p3;
    ge_scalarmult_base(&aG_p3, a);
    ge_p3_tobytes(aG, &aG_p3);

    ge_p3 H_p3;
    if (ge_frombytes_vartime(&H_p3, H) != 0) {
        logf_("clsag_prepare: H not on curve");
        return;
    }

    ge_p2 aH_p2;
    ge_scalarmult(&aH_p2, a, &H_p3);
    ge_tobytes(aH, &aH_p2);

    ge_p2 I_p2;
    ge_scalarmult(&I_p2, p, &H_p3);
    ge_tobytes(I, &I_p2);

    ge_p2 D_p2;
    ge_scalarmult(&D_p2, z, &H_p3);
    ge_tobytes(D, &D_p2);
}

// ===========================================================================
// clsag_sign
// ===========================================================================
static void clsag_sign(const uint8_t c[32], const uint8_t a[32],
                       const uint8_t p[32], const uint8_t z[32],
                       const uint8_t mu_P[32], const uint8_t mu_C[32],
                       uint8_t s[32])
{
    uint8_t s0_p_mu_P[32];
    sc_mul(s0_p_mu_P, mu_P, p);

    uint8_t s0_add_z_mu_C[32];
    sc_muladd(s0_add_z_mu_C, mu_C, z, s0_p_mu_P);

    sc_mulsub(s, c, s0_add_z_mu_C, a);
}

// ===========================================================================
// addKeys_aGbBcC: L = a*G + b*B + c*C
// ===========================================================================
static void addKeys_aGbBcC(uint8_t out[32],
                           const uint8_t a[32],
                           const uint8_t b[32], const ge_dsmp B,
                           const uint8_t c[32], const ge_dsmp C)
{
    ge_p2 result;
    ge_triple_scalarmult_base_vartime(&result, a, b, B, c, C);
    ge_tobytes(out, &result);
}

// ===========================================================================
// addKeys_aAbBcC: R = a*A + b*B + c*C
// ===========================================================================
static void addKeys_aAbBcC(uint8_t out[32],
                           const uint8_t a[32], const ge_dsmp A,
                           const uint8_t b[32], const ge_dsmp B,
                           const uint8_t c[32], const ge_dsmp C)
{
    ge_p2 result;
    ge_triple_scalarmult_precomp_vartime(&result, a, A, b, B, c, C);
    ge_tobytes(out, &result);
}

// ===========================================================================
// clsag_prove — главная функция
// ===========================================================================
bool clsag_prove(const uint8_t message[32],
                 const uint8_t P[][32],
                 const uint8_t C_nonzero[][32],
                 const uint8_t C_offset[32],
                 const uint8_t p[32],
                 const uint8_t z[32],
                 uint32_t l,
                 uint32_t n,
                 clsag_t *out)
{
    // ---- Все буферы static, чтобы не переполнять стек ----
    static uint8_t a[32], aG[32], aH[32], D_unc[32];
    static ge_dsmp I_precomp, D_precomp;
    static ge_dsmp P_precomp, C_precomp, H_precomp;
    static ge_p3 P_i_p3, C_i_p3, C_i_p3_final, Hi_p3;
    static ge_p3 I_p3, D_p3;
    static ge_cached C_offset_cached;
    static uint8_t c_p[32], c_c[32], L[32], R[32], c_new[32], c[32];
    static uint8_t mu_P[32], mu_C[32];

    static uint8_t mu_buf[CLSAG_MAX_RING * 2 * 32 + 4 * 32];
    static uint8_t c_hash_buf[CLSAG_MAX_RING * 2 * 32 + 5 * 32];

    if (n < 2 || n > CLSAG_MAX_RING) {
        logf_("clsag: invalid n=%u", n);
        return false;
    }
    if (l >= n) {
        logf_("clsag: invalid l=%u (n=%u)", l, n);
        return false;
    }

    memset(out, 0, sizeof(*out));

    size_t mu_buf_len = (2 * n + 4) * 32;
    size_t c_buf_len  = (2 * n + 5) * 32;

    // ШАГ 1: H = Hp(P[l])
    uint8_t H[32];
    {
        ge_p3 H_p3;
        hash_to_p3(P[l], &H_p3);
        ge_p3_tobytes(H, &H_p3);
    }
    log_hex32("clsag: P[l]", P[l]);
    log_hex32("clsag: H (=Hp(P[l]))", H);

    // ШАГ 2: нонсы — детерминированно из полного контекста, с подмешиванием ГСЧ
    static uint8_t nonce_seed_buf[32];
    clsag_nonce_seed(nonce_seed_buf, p, z, message, H, C_offset, P, C_nonzero, l, n);
    clsag_nonce_derive(a, nonce_seed_buf, "a", 0);

    clsag_prepare(p, z, out->I, D_unc, H, a, aG, aH);

    log_hex32("clsag: I", out->I);
    log_hex32("clsag: D_unc", D_unc);
    log_hex32("clsag: aG", aG);
    log_hex32("clsag: aH", aH);

    // ШАГ 3: sig.D = D_unc * INV_EIGHT
    if (ge_frombytes_vartime(&D_p3, D_unc) != 0) {
        logf_("clsag: D_unc not on curve");
        return false;
    }
    {
        ge_p2 D_inv8_p2;
        ge_scalarmult(&D_inv8_p2, INV_EIGHT_BYTES, &D_p3);
        ge_tobytes(out->D, &D_inv8_p2);
    }
    log_hex32("clsag: D (INV_EIGHT)", out->D);

    // ШАГ 4: Precomp I и D_unc
    if (ge_frombytes_vartime(&I_p3, out->I) != 0) {
        logf_("clsag: I not on curve");
        return false;
    }
    ge_dsm_precomp(I_precomp, &I_p3);
    ge_dsm_precomp(D_precomp, &D_p3);

    // ШАГ 5: mu_P, mu_C
    memset(mu_buf, 0, 32);
    memcpy(mu_buf, HASH_KEY_CLSAG_AGG_0, sizeof(HASH_KEY_CLSAG_AGG_0) - 1);
    for (uint32_t i = 0; i < n; i++) {
        memcpy(mu_buf + (i + 1) * 32, P[i], 32);
    }
    for (uint32_t i = 0; i < n; i++) {
        memcpy(mu_buf + (n + 1 + i) * 32, C_nonzero[i], 32);
    }
    memcpy(mu_buf + (2 * n + 1) * 32, out->I, 32);
    memcpy(mu_buf + (2 * n + 2) * 32, out->D, 32);
    memcpy(mu_buf + (2 * n + 3) * 32, C_offset, 32);
    hash_to_scalar(mu_buf, mu_buf_len, mu_P);

    memset(mu_buf, 0, 32);
    memcpy(mu_buf, HASH_KEY_CLSAG_AGG_1, sizeof(HASH_KEY_CLSAG_AGG_1) - 1);
    for (uint32_t i = 0; i < n; i++) {
        memcpy(mu_buf + (i + 1) * 32, P[i], 32);
    }
    for (uint32_t i = 0; i < n; i++) {
        memcpy(mu_buf + (n + 1 + i) * 32, C_nonzero[i], 32);
    }
    memcpy(mu_buf + (2 * n + 1) * 32, out->I, 32);
    memcpy(mu_buf + (2 * n + 2) * 32, out->D, 32);
    memcpy(mu_buf + (2 * n + 3) * 32, C_offset, 32);
    hash_to_scalar(mu_buf, mu_buf_len, mu_C);

    log_hex32("clsag: mu_P", mu_P);
    log_hex32("clsag: mu_C", mu_C);

    // ШАГ 6: c = Hs("CLSAG_round" || P || C_nonzero || C_offset || message || aG || aH)
    memset(c_hash_buf, 0, 32);
    memcpy(c_hash_buf, HASH_KEY_CLSAG_ROUND, sizeof(HASH_KEY_CLSAG_ROUND) - 1);
    for (uint32_t i = 0; i < n; i++) {
        memcpy(c_hash_buf + (i + 1) * 32, P[i], 32);
        memcpy(c_hash_buf + (n + 1 + i) * 32, C_nonzero[i], 32);
    }
    memcpy(c_hash_buf + (2 * n + 1) * 32, C_offset, 32);
    memcpy(c_hash_buf + (2 * n + 2) * 32, message, 32);
    memcpy(c_hash_buf + (2 * n + 3) * 32, aG, 32);
    memcpy(c_hash_buf + (2 * n + 4) * 32, aH, 32);

    hash_to_scalar(c_hash_buf, c_buf_len, c);
    log_hex32("clsag: c (initial)", c);

    // ШАГ 7: C_offset в cached
    ge_p3 C_offset_p3;
    if (ge_frombytes_vartime(&C_offset_p3, C_offset) != 0) {
        logf_("clsag: C_offset not on curve");
        return false;
    }
    ge_p3_to_cached(&C_offset_cached, &C_offset_p3);

    // =========================================================================
    // ШАГ 8: Цикл по decoy
    //
    // ПОРЯДОК КАК В MONERO CLSAG_Gen:
    //   i = (l+1) % n;
    //   if (i == 0) c1 = c;                  // до цикла
    //   while (i != l) {
    //       compute L, R
    //       c = Hs(c_to_hash, L, R);
    //       i = (i+1) % n;
    //       if (i == 0) c1 = c;             // ПОСЛЕ инкремента i
    //   }
    // =========================================================================
    uint32_t i = (l + 1) % n;
    if (i == 0) {
        memcpy(out->c1, c, 32);
    }

    while (i != l) {
        // Подставные s[i] — не нонсы дискретного логарифма, они публикуются
        // в транзакции. Но они обязаны быть непредсказуемы снаружи: если поток
        // ГСЧ предсказуем, то индекс, на котором s[i] не совпал с предсказанием,
        // и есть реальный вход — анонимность кольца рассыпается целиком.
        clsag_nonce_derive(out->s[i], nonce_seed_buf, "s", i);

        // c_p = c * mu_P
        sc_mul(c_p, mu_P, c);
        // c_c = c * mu_C
        sc_mul(c_c, mu_C, c);

        // C[i] = C_nonzero[i] - C_offset
        if (ge_frombytes_vartime(&C_i_p3, C_nonzero[i]) != 0) {
            logf_("clsag: C_nonzero[%u] not on curve", i);
            return false;
        }
        {
            ge_p1p1 C_i_p1p1;
            ge_sub(&C_i_p1p1, &C_i_p3, &C_offset_cached);
            ge_p1p1_to_p3(&C_i_p3_final, &C_i_p1p1);
        }

        // Precomp P[i] и C[i]
        if (ge_frombytes_vartime(&P_i_p3, P[i]) != 0) {
            logf_("clsag: P[%u] not on curve", i);
            return false;
        }
        ge_dsm_precomp(P_precomp, &P_i_p3);
        ge_dsm_precomp(C_precomp, &C_i_p3_final);

        // L = s[i]*G + c_p*P[i] + c_c*C[i]
        addKeys_aGbBcC(L, out->s[i], c_p, P_precomp, c_c, C_precomp);

        // R = s[i]*Hp(P[i]) + c_p*I + c_c*D_unc
        hash_to_p3(P[i], &Hi_p3);
        ge_dsm_precomp(H_precomp, &Hi_p3);
        addKeys_aAbBcC(R, out->s[i], H_precomp, c_p, I_precomp, c_c, D_precomp);

        // c_new = Hs(c_to_hash с L, R)
        memcpy(c_hash_buf + (2 * n + 3) * 32, L, 32);
        memcpy(c_hash_buf + (2 * n + 4) * 32, R, 32);
        hash_to_scalar(c_hash_buf, c_buf_len, c_new);

        memcpy(c, c_new, 32);

        i = (i + 1) % n;
        if (i == 0) {
            memcpy(out->c1, c, 32);     // ← ПОСЛЕ инкремента i, Monero-стиль
        }
    }

    // ШАГ 9: s[l] = clsag_sign(c, a, p, z, mu_P, mu_C)
    clsag_sign(c, a, p, z, mu_P, mu_C, out->s[l]);

    // ---- Очистка ----
    memset(nonce_seed_buf, 0, 32);
    memset(a, 0, 32);
    memset(mu_P, 0, 32);
    memset(mu_C, 0, 32);
    memset(c, 0, 32);

    logf_("clsag: done, n=%u l=%u", n, l);
    return true;
}