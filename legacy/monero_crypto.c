// monero_crypto.c
//
// Реализация key image + подписи для cold-кошелька Monero на ESP32-S3.
//
// ФОРМУЛА для обычных адресов (проверена эмпирически):
//   derivation = 8 * view_sk * tx_pubkey
//   hs         = Hs(derivation || varint_leb128(idx))
//   x          = hs + spend_sk_reduced  (mod l)
//   P          = x * G                                 (сверка с output_pubkey)
//
// Для subaddress outputs (subaddr_major/minor != 0) проверяем ДВА варианта:
//   Вариант A: derivation = 8 * view_sk * tx_pubkey (как для обычных),
//              x = hs + spend_sk
//   Вариант B: derivation = 8 * view_sk * tx_pubkey (как для обычных),
//              x = hs + (spend_sk + m),  где
//              m = Hs("SubAddr\0" || view_sk || major_le || minor_le)
//
// Побеждает тот, у которого P = output_pubkey.

#include "monero_crypto.h"
#include "hash-ops.h"
#include "crypto-ops.h"
#include "keccak.h"
#include <string.h>
#include <stdio.h>

extern void platform_random_bytes(uint8_t *buf, size_t n);
extern void platform_log(const char *msg);

// ---------------------------------------------------------------------------
// hash_to_scalar
// ---------------------------------------------------------------------------
void hash_to_scalar(const void *data, size_t length, uint8_t out[32]) {
    cn_fast_hash(data, length, out);
    sc_reduce32(out);
}

// ---------------------------------------------------------------------------
// Отладочный hexdump
// ---------------------------------------------------------------------------
static void log_hex(const char *prefix, const uint8_t *data, size_t n) {
    char buf[160];
    size_t show = n < 32 ? n : 32;
    int off = 0;
    off += snprintf(buf, sizeof(buf), "%s(%u)=", prefix, (unsigned)n);
    for (size_t i = 0; i < show && off + 3 < (int)sizeof(buf); i++) {
        off += snprintf(buf + off, sizeof(buf) - off, "%02x", data[i]);
    }
    platform_log(buf);
}

// ---------------------------------------------------------------------------
// biased_hash_to_ec: hash-to-point Hp(P).
// ---------------------------------------------------------------------------
static void biased_hash_to_ec(const uint8_t pubkey[32], ge_p3 *res) {
    uint8_t h[32];
    cn_fast_hash(pubkey, 32, h);

    ge_p2 point;
    ge_fromfe_frombytes_vartime(&point, h);

    ge_p1p1 point2;
    ge_mul8(&point2, &point);

    ge_p1p1_to_p3(res, &point2);
}

// ---------------------------------------------------------------------------
// crypto_generate_key_derivation
// D = 8 * key2 * key1
// ---------------------------------------------------------------------------
bool crypto_generate_key_derivation(const uint8_t tx_pubkey[32],
                                    const uint8_t view_secret_key[32],
                                    uint8_t derivation_out[32])
{
    ge_p3 R_p3;
    if (ge_frombytes_vartime(&R_p3, tx_pubkey) != 0) return false;

    ge_p2 D_p2;
    ge_scalarmult(&D_p2, view_secret_key, &R_p3);

    ge_p1p1 D_p1p1;
    ge_mul8(&D_p1p1, &D_p2);

    ge_p2 D_final;
    ge_p1p1_to_p2(&D_final, &D_p1p1);

    ge_tobytes(derivation_out, &D_final);
    return true;
}

// ---------------------------------------------------------------------------
// crypto_secret_key_to_public_key
// ---------------------------------------------------------------------------
void crypto_secret_key_to_public_key(const uint8_t sec[32], uint8_t pub[32]) {
    ge_p3 p3;
    ge_scalarmult_base(&p3, sec);
    ge_p3_tobytes(pub, &p3);
}

// ---------------------------------------------------------------------------
// crypto_generate_subaddress_secret_key
// m = Hs("SubAddr\0" || view_sk || major(u32 LE) || minor(u32 LE))
// ---------------------------------------------------------------------------
void crypto_generate_subaddress_secret_key(const uint8_t view_sk[32],
                                           uint32_t major, uint32_t minor,
                                           uint8_t out_m[32])
{
    uint8_t buf[48];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "SubAddr", 7);       // 7 символов + \0 (buf[7] = 0)
    memcpy(buf + 8, view_sk, 32);

    buf[40] = (uint8_t)(major);
    buf[41] = (uint8_t)(major >>  8);
    buf[42] = (uint8_t)(major >> 16);
    buf[43] = (uint8_t)(major >> 24);

    buf[44] = (uint8_t)(minor);
    buf[45] = (uint8_t)(minor >>  8);
    buf[46] = (uint8_t)(minor >> 16);
    buf[47] = (uint8_t)(minor >> 24);

    hash_to_scalar(buf, sizeof(buf), out_m);
}

// ---------------------------------------------------------------------------
// derive_and_sign_key_image
//
// derivation задаётся снаружи.
// hs = Hs(derivation || varint_leb128(idx))
// x  = hs + spend_sk (mod l)
// P  = x*G  (сверка с output_pubkey)
// Hp = biased_hash_to_ec(output_pubkey)
// I  = x*Hp (key image)
// ---------------------------------------------------------------------------
bool derive_and_sign_key_image(
    const uint8_t derivation[32],
    uint32_t out_index_in_tx,
    const uint8_t output_pubkey[32],
    const uint8_t spend_secret_key[32],
    uint8_t key_image_out[32],
    uint8_t sig_c_out[32],
    uint8_t sig_r_out[32])
{
    platform_log("derive_and_sign_key_image: start");

    // 1) hs = Hs(derivation || varint_leb128(idx))
    uint8_t buf[32 + 10];
    memcpy(buf, derivation, 32);
    size_t vlen = 0;
    {
        uint64_t v = out_index_in_tx;
        while (v >= 0x80) {
            buf[32 + vlen++] = (uint8_t)(v & 0x7f) | 0x80;
            v >>= 7;
        }
        buf[32 + vlen++] = (uint8_t)v;
    }
    uint8_t hs[32];
    hash_to_scalar(buf, 32 + vlen, hs);
    log_hex("kai: hs", hs, 32);

    // 2) x = hs + spend_sk (mod l)
    uint8_t x[32];
    sc_add(x, hs, spend_secret_key);
    log_hex("kai: x", x, 32);

    // 3) P_check = x*G
    ge_p3 pcheck_p3;
    ge_scalarmult_base(&pcheck_p3, x);
    uint8_t pcheck_bytes[32];
    ge_p3_tobytes(pcheck_bytes, &pcheck_p3);
    log_hex("kai: P_check", pcheck_bytes, 32);
    log_hex("kai: P_expected", output_pubkey, 32);

    if (memcmp(pcheck_bytes, output_pubkey, 32) != 0) {
        platform_log("derive_and_sign_key_image: pubkey mismatch");
        memset(x, 0, sizeof(x));
        memset(hs, 0, sizeof(hs));
        return false;
    }

    // 4) Hp(P)
    ge_p3 hp_p3;
    biased_hash_to_ec(output_pubkey, &hp_p3);

    // 5) I = x * Hp
    ge_p2 i_p2;
    ge_scalarmult(&i_p2, x, &hp_p3);
    ge_tobytes(key_image_out, &i_p2);
    log_hex("kai: key_image", key_image_out, 32);

    // 6) k = random scalar
    uint8_t k[32];
    platform_random_bytes(k, 32);
    sc_reduce32(k);

    // 7) A = k*G, B = k*Hp
    ge_p3 a_p3;
    ge_scalarmult_base(&a_p3, k);
    uint8_t a_bytes[32];
    ge_p3_tobytes(a_bytes, &a_p3);

    ge_p2 b_p2;
    ge_scalarmult(&b_p2, k, &hp_p3);
    uint8_t b_bytes[32];
    ge_tobytes(b_bytes, &b_p2);

    // 8) c = Hs(I || A || B)
    uint8_t hbuf[96];
    memcpy(hbuf,      key_image_out, 32);
    memcpy(hbuf + 32, a_bytes,       32);
    memcpy(hbuf + 64, b_bytes,       32);
    hash_to_scalar(hbuf, sizeof(hbuf), sig_c_out);

    // 9) r = k - c*x
    sc_mulsub(sig_r_out, sig_c_out, x, k);

    memset(x, 0, sizeof(x));
    memset(hs, 0, sizeof(hs));
    memset(k, 0, sizeof(k));

    platform_log("derive_and_sign_key_image: done");
    return true;
}

// ---------------------------------------------------------------------------
// derive_and_sign_key_image_alt_spend
//
// Отличается только тем, что вместо spend_sk используется
// spend_sk_alt = spend_sk + m. Всё остальное — как в основной функции.
// Используется для проверки гипотезы о subaddress.
// ---------------------------------------------------------------------------
static bool derive_and_sign_key_image_with_custom_spend(
    const uint8_t derivation[32],
    uint32_t out_index_in_tx,
    const uint8_t output_pubkey[32],
    const uint8_t spend_sk_custom[32],
    uint8_t key_image_out[32],
    uint8_t sig_c_out[32],
    uint8_t sig_r_out[32])
{
    platform_log("derive_and_sign_key_image(custom spend): start");

    uint8_t buf[32 + 10];
    memcpy(buf, derivation, 32);
    size_t vlen = 0;
    {
        uint64_t v = out_index_in_tx;
        while (v >= 0x80) {
            buf[32 + vlen++] = (uint8_t)(v & 0x7f) | 0x80;
            v >>= 7;
        }
        buf[32 + vlen++] = (uint8_t)v;
    }
    uint8_t hs[32];
    hash_to_scalar(buf, 32 + vlen, hs);
    log_hex("kai: hs", hs, 32);

    uint8_t x[32];
    sc_add(x, hs, spend_sk_custom);
    log_hex("kai: x", x, 32);

    ge_p3 pcheck_p3;
    ge_scalarmult_base(&pcheck_p3, x);
    uint8_t pcheck_bytes[32];
    ge_p3_tobytes(pcheck_bytes, &pcheck_p3);
    log_hex("kai: P_check", pcheck_bytes, 32);
    log_hex("kai: P_expected", output_pubkey, 32);

    if (memcmp(pcheck_bytes, output_pubkey, 32) != 0) {
        platform_log("derive_and_sign_key_image(custom spend): mismatch");
        memset(x, 0, sizeof(x));
        memset(hs, 0, sizeof(hs));
        return false;
    }

    ge_p3 hp_p3;
    biased_hash_to_ec(output_pubkey, &hp_p3);

    ge_p2 i_p2;
    ge_scalarmult(&i_p2, x, &hp_p3);
    ge_tobytes(key_image_out, &i_p2);
    log_hex("kai: key_image", key_image_out, 32);

    uint8_t k[32];
    platform_random_bytes(k, 32);
    sc_reduce32(k);

    ge_p3 a_p3;
    ge_scalarmult_base(&a_p3, k);
    uint8_t a_bytes[32];
    ge_p3_tobytes(a_bytes, &a_p3);

    ge_p2 b_p2;
    ge_scalarmult(&b_p2, k, &hp_p3);
    uint8_t b_bytes[32];
    ge_tobytes(b_bytes, &b_p2);

    uint8_t hbuf[96];
    memcpy(hbuf,      key_image_out, 32);
    memcpy(hbuf + 32, a_bytes,       32);
    memcpy(hbuf + 64, b_bytes,       32);
    hash_to_scalar(hbuf, sizeof(hbuf), sig_c_out);

    sc_mulsub(sig_r_out, sig_c_out, x, k);

    memset(x, 0, sizeof(x));
    memset(hs, 0, sizeof(hs));
    memset(k, 0, sizeof(k));

    platform_log("derive_and_sign_key_image(custom spend): done");
    return true;
}

// ---------------------------------------------------------------------------
// derive_and_sign_key_image_from_viewkey
//
// Для обычных адресов: derivation = 8*view_sk*R, x = hs + spend_sk.
// Для subaddress — проверяем ДВА варианта и побеждает тот, у которого
// P совпадает с output_pubkey.
// ---------------------------------------------------------------------------
bool derive_and_sign_key_image_from_viewkey(
    const uint8_t tx_pubkey[32],
    uint32_t out_index_in_tx,
    const uint8_t output_pubkey[32],
    const uint8_t view_secret_key[32],
    const uint8_t spend_secret_key[32],
    uint8_t key_image_out[32],
    uint8_t sig_c_out[32],
    uint8_t sig_r_out[32],
    uint32_t subaddr_major,
    uint32_t subaddr_minor)
{
    uint8_t derivation[32];

    // derivation всегда одинаковая: 8 * view_sk * R
    if (!crypto_generate_key_derivation(tx_pubkey, view_secret_key, derivation)) {
        platform_log("from_viewkey: invalid tx_pubkey");
        return false;
    }
    log_hex("from_viewkey: derivation", derivation, 32);

    // Для обычных адресов — стандартный путь.
    if (subaddr_major == 0 && subaddr_minor == 0) {
        bool ok = derive_and_sign_key_image(derivation, out_index_in_tx,
                                            output_pubkey, spend_secret_key,
                                            key_image_out, sig_c_out, sig_r_out);
        memset(derivation, 0, sizeof(derivation));
        return ok;
    }

    // --- Subaddress: два варианта ---

    // Вариант A: x = hs + spend_sk (то же, что для обычных)
    platform_log("from_viewkey: subaddress, try variant A (x = hs + spend_sk)");
    bool okA = derive_and_sign_key_image(derivation, out_index_in_tx,
                                         output_pubkey, spend_secret_key,
                                         key_image_out, sig_c_out, sig_r_out);
    if (okA) {
        platform_log("*** SUBADDR MATCH: variant A (x = hs + spend_sk) ***");
        memset(derivation, 0, sizeof(derivation));
        return true;
    }

    // Вариант B: x = hs + (spend_sk + m),
    //   m = Hs("SubAddr\0" || view_sk || major_le || minor_le)
    platform_log("from_viewkey: subaddress, try variant B (x = hs + spend_sk + m)");
    uint8_t m[32];
    crypto_generate_subaddress_secret_key(view_secret_key,
                                          subaddr_major, subaddr_minor, m);
    log_hex("from_viewkey: m", m, 32);

    uint8_t spend_sub[32];
    sc_add(spend_sub, spend_secret_key, m);
    log_hex("from_viewkey: spend_sub = spend_sk + m", spend_sub, 32);

    bool okB = derive_and_sign_key_image_with_custom_spend(
                    derivation, out_index_in_tx, output_pubkey, spend_sub,
                    key_image_out, sig_c_out, sig_r_out);
    memset(m, 0, sizeof(m));
    memset(spend_sub, 0, sizeof(spend_sub));

    if (okB) {
        platform_log("*** SUBADDR MATCH: variant B (x = hs + spend_sk + m) ***");
        memset(derivation, 0, sizeof(derivation));
        return true;
    }

    platform_log("from_viewkey: subaddress NO MATCH (A and B both failed)");
    memset(derivation, 0, sizeof(derivation));
    return false;
}

// ===========================================================================
// Schnorr sign / verify
// ===========================================================================

static void random_scalar_nonzero(uint8_t out[32]) {
    static const uint8_t limit[32] = {
        0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29, 0x8f, 0x30, 0x82, 0x8c,
        0x0b, 0xa4, 0x10, 0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0
    };
    while (1) {
        platform_random_bytes(out, 32);
        int less = 0;
        for (int i = 31; i >= 0; --i) {
            if (out[i] < limit[i]) { less = 1; break; }
            if (out[i] > limit[i]) { less = 0; break; }
        }
        if (!less) continue;
        sc_reduce32(out);
        if (sc_isnonzero(out)) break;
    }
}

bool crypto_generate_signature(const uint8_t hash[32],
                               const uint8_t pub[32],
                               const uint8_t sec[32],
                               uint8_t sig[64])
{
    ge_p3 tmp3;
    uint8_t k[32];
    uint8_t buf[96];

    memcpy(buf,      hash, 32);
    memcpy(buf + 32, pub,  32);

retry:
    random_scalar_nonzero(k);
    ge_scalarmult_base(&tmp3, k);
    ge_p3_tobytes(buf + 64, &tmp3);

    uint8_t c[32];
    hash_to_scalar(buf, sizeof(buf), c);
    if (!sc_isnonzero(c)) goto retry;

    uint8_t r[32];
    sc_mulsub(r, c, sec, k);
    if (!sc_isnonzero(r)) goto retry;

    memcpy(sig,      c, 32);
    memcpy(sig + 32, r, 32);

    memset(k, 0, 32);
    return true;
}

bool crypto_check_signature(const uint8_t hash[32],
                            const uint8_t pub[32],
                            const uint8_t sig[64])
{
    const uint8_t *c = sig;
    const uint8_t *r = sig + 32;

    if (sc_check(c) != 0 || sc_check(r) != 0 || !sc_isnonzero(c)) return false;

    ge_p3 A_p3;
    if (ge_frombytes_vartime(&A_p3, pub) != 0) return false;

    ge_p2 comm_p2;
    ge_double_scalarmult_base_vartime(&comm_p2, c, &A_p3, r);

    uint8_t buf[96];
    memcpy(buf,      hash, 32);
    memcpy(buf + 32, pub,  32);
    ge_tobytes(buf + 64, &comm_p2);

    static const uint8_t infinity[32] = {
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    if (memcmp(buf + 64, infinity, 32) == 0) return false;

    uint8_t c_check[32];
    hash_to_scalar(buf, sizeof(buf), c_check);

    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= (uint8_t)(c[i] ^ c_check[i]);
    return diff == 0;
}