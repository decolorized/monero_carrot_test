#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Хэши / скаляры (как в Monero)
// ---------------------------------------------------------------------------
// Внимание: cn_fast_hash объявлена в hash-ops.h (оригинальный monero-файл).
// Если она нужна — подключайте hash-ops.h.

// Hs(data) = cn_fast_hash(data) приведённый по модулю l (sc_reduce32).
void hash_to_scalar(const void *data, size_t length, uint8_t out[32]);

// ---------------------------------------------------------------------------
// Основная операция ESP32 как крипто-модуля.
// ---------------------------------------------------------------------------

// derivation задаётся снаружи (32 байта, compressed point).
bool derive_and_sign_key_image(
    const uint8_t derivation[32],
    uint32_t out_index_in_tx,
    const uint8_t output_pubkey[32],
    const uint8_t spend_secret_key[32],
    uint8_t key_image_out[32],
    uint8_t sig_c_out[32],
    uint8_t sig_r_out[32]);

// Сама считает derivation = 8 * view_sk_or_m * tx_pubkey,
// где view_sk_or_m = view_sk для обычных адресов,
// либо m = Hs("SubAddr\0"||view_sk||major_le||minor_le) для subaddress.
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
    uint32_t subaddr_minor);

// ---------------------------------------------------------------------------
// Schnorr-подпись в стиле crypto::generate_signature / check_signature.
// ---------------------------------------------------------------------------

bool crypto_generate_signature(const uint8_t hash[32],
                               const uint8_t pub[32],
                               const uint8_t sec[32],
                               uint8_t sig[64]);

bool crypto_check_signature(const uint8_t hash[32],
                            const uint8_t pub[32],
                            const uint8_t sig[64]);

// ---------------------------------------------------------------------------
// curve25519 helpers
// ---------------------------------------------------------------------------

// derivation = 8 * view_secret_key * tx_pubkey (compressed point).
bool crypto_generate_key_derivation(const uint8_t tx_pubkey[32],
                                    const uint8_t view_secret_key[32],
                                    uint8_t derivation_out[32]);

void crypto_secret_key_to_public_key(const uint8_t sec[32], uint8_t pub[32]);

// m = Hs("SubAddr\0" || view_sk || major(u32 LE) || minor(u32 LE))
// Используется вместо view_sk при обработке subaddress outputs.
void crypto_generate_subaddress_secret_key(const uint8_t view_sk[32],
                                           uint32_t major, uint32_t minor,
                                           uint8_t out_m[32]);

#ifdef __cplusplus
}
#endif