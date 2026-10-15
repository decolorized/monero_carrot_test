// cw_crypto.h — примитивы Monero (CryptoNote, Carrot, FCMP++) для холодного
// подписанта. Всё в байтах: точки и скаляры по 32 байта, little-endian, как
// в monero (src/crypto, src/carrot_core, src/fcmp_pp).
//
// Эталон: monero-project/monero, ветка fcmp++-beta-stressnet-v3
// (seraphis-migration/monero cf273dc), monero-oxide 31c26d9.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- платформа (реализуется в .ino или в хостовой обвязке) ----------------
void cw_random(uint8_t *buf, size_t n);

// ---- генераторы ------------------------------------------------------------
extern const uint8_t CW_G[32];
extern const uint8_t CW_H[32];
extern const uint8_t CW_T[32];
extern const uint8_t CW_U[32];
extern const uint8_t CW_V[32];
extern const uint8_t CW_IDENTITY[32];   // {1, 0, ...}

// ---- хеши ------------------------------------------------------------------
// Keccak-256 (cn_fast_hash)
void cw_keccak(const void *data, size_t len, uint8_t out[32]);
// H_s: keccak + sc_reduce32
void cw_hash_to_scalar(const void *data, size_t len, uint8_t out[32]);
// Carrot H_n / H_x: Blake2b, personal "Monero", key 32 байта или NULL.
void cw_blake2b_carrot(const void *key32, const void *data, size_t len,
                       uint8_t *out, size_t outlen);
void cw_derive_scalar(const void *key32, const void *data, size_t len,
                      uint8_t out[32]);

// Транскрипт Carrot: [len(domain)] domain || поля как есть.
typedef struct {
    uint8_t buf[320];
    size_t  n;
} cw_tr_t;
void cw_tr_init(cw_tr_t *t, const char *domain);
void cw_tr_add(cw_tr_t *t, const void *data, size_t len);
void cw_tr_u8(cw_tr_t *t, uint8_t v);
void cw_tr_u32(cw_tr_t *t, uint32_t v);
void cw_tr_u64(cw_tr_t *t, uint64_t v);
void cw_tr_wipe(cw_tr_t *t);

// ---- скаляры ---------------------------------------------------------------
void cw_sc_reduce64(uint8_t out[32], const uint8_t in[64]);
void cw_sc_add(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]);
void cw_sc_sub(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]);
void cw_sc_mul(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]);
void cw_sc_muladd(uint8_t r[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32]); // a*b+c
void cw_sc_mulsub(uint8_t r[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32]); // c-a*b
void cw_sc_neg(uint8_t r[32], const uint8_t a[32]);
bool cw_sc_is_zero(const uint8_t a[32]);
bool cw_sc_is_canonical(const uint8_t a[32]);
void cw_sc_from_u64(uint8_t r[32], uint64_t v);
// случайный скаляр с подмешиванием секрета и контекста (hedged)
void cw_sc_hedged(uint8_t out[32], const void *secret, size_t secret_len,
                  const void *ctx, size_t ctx_len, uint32_t counter);

// ---- точки -----------------------------------------------------------------
bool cw_pt_valid(const uint8_t P[32]);
void cw_pt_base(uint8_t out[32], const uint8_t s[32]);                        // s*G
bool cw_pt_mul(uint8_t out[32], const uint8_t s[32], const uint8_t P[32]);    // s*P
bool cw_pt_mul8(uint8_t out[32], const uint8_t P[32]);                        // 8*P
bool cw_pt_add(uint8_t out[32], const uint8_t P[32], const uint8_t Q[32]);
bool cw_pt_sub(uint8_t out[32], const uint8_t P[32], const uint8_t Q[32]);
// a*P + b*Q (переменное время)
bool cw_pt_mul2(uint8_t out[32], const uint8_t a[32], const uint8_t P[32],
                const uint8_t b[32], const uint8_t Q[32]);
// x*G + y*T
void cw_pt_gt(uint8_t out[32], const uint8_t x[32], const uint8_t y[32]);
bool cw_pt_in_main_subgroup(const uint8_t P[32]);
bool cw_pt_eq(const uint8_t a[32], const uint8_t b[32]);

// C = mask*G + amount*H
void cw_commit(uint8_t out[32], uint64_t amount, const uint8_t mask[32]);

// ---- hash-to-point ---------------------------------------------------------
void cw_hp_biased(uint8_t out[32], const uint8_t P[32]);                 // 8*ge_fromfe(keccak(P))
void cw_hp_unbiased(uint8_t out[32], const void *pre, size_t len);       // Blake2b-512 -> 2 Elligator
void cw_ki_generator(uint8_t out[32], const uint8_t O[32], bool biased);

// ---- X25519 (mx25519 portable, без clamp) ----------------------------------
void cw_x25519_base(uint8_t out[32], const uint8_t scalar[32]);
void cw_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32]);
bool cw_ed_to_x25519(uint8_t out[32], const uint8_t ed[32]);            // ConvertPointE
bool cw_ed_mul_to_x25519(uint8_t out[32], const uint8_t s[32], const uint8_t ed[32]); // ConvertPointE(s*P)

// ---- CryptoNote (legacy) ---------------------------------------------------
bool cw_key_derivation(uint8_t out[32], const uint8_t R[32], const uint8_t k[32]);  // 8*k*R
void cw_derivation_to_scalar(uint8_t out[32], const uint8_t D[32], uint64_t idx);
void cw_legacy_subaddr_ext(uint8_t out[32], const uint8_t k_view[32], uint32_t major, uint32_t minor);
// Подпись Шнорра (crypto::generate_signature / check_signature)
void cw_generate_signature(uint8_t sig[64], const uint8_t hash[32],
                           const uint8_t pub[32], const uint8_t sec[32]);
bool cw_check_signature(const uint8_t sig[64], const uint8_t hash[32], const uint8_t pub[32]);
// Кольцевая подпись из одного члена (crypto::generate_ring_signature, n=1):
// доказательство L = x*Hp_biased(O), O = x*G.
void cw_ring1_signature(uint8_t sig[64], const uint8_t hash[32], const uint8_t key_image[32],
                        const uint8_t O[32], const uint8_t x[32]);
bool cw_ring1_check(const uint8_t sig[64], const uint8_t hash[32], const uint8_t key_image[32],
                    const uint8_t O[32]);

// ---- память ----------------------------------------------------------------
void cw_wipe(void *p, size_t n);

#ifdef __cplusplus
}
#endif
