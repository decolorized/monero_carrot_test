// Сборка keyimages.bin для Monero (v3, magic "Monero key image export\003").
//
// Формат файла (см. wallet2.cpp::export_key_images):
//   magic  "Monero key image export\003"  (26 байт)
//   iv     8 байт (chacha_iv)
//   ct     chacha20(plaintext)             (длина = len(plaintext))
//   sig    64 байта (crypto::signature, Schnorr от keccak256(iv||ct))
//
// plaintext:
//   offset      : u32 LE
//   spend_pub   : 32
//   view_pub    : 32
//   nrec × (key_image(32) || sig_c(32) || sig_r(32))
//
// ChaCha-ключ для шифрования = cn_slow_hash(view_sk, 32, key, 0, 0, 0)
// (kdf_rounds = 1). Считается в caller'е — сюда передаётся уже готовый
// view_sk, и внутри мы вызываем cn_slow_hash через monero_crypto.h.

#include "keyimages_writer.h"
#include "chacha20.h"
#include "monero_crypto.h"
#include "keccak.h"
#include <string.h>
#include <stdlib.h>

#define KI_MAGIC "Monero key image export\003"
#define KI_MAGIC_LEN (sizeof(KI_MAGIC) - 1)

// Реализуется в .ino / платформенном коде.
extern void platform_random_bytes(uint8_t *buf, size_t n);

// Реализуется в slow-hash.c.
extern void cn_slow_hash(const void *data, size_t length, char *hash,
                         int variant, int prehashed, uint64_t height);

static void put_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

size_t build_keyimages_bin(const uint8_t view_sk[32],
                           const uint8_t spend_pub[32],
                           const uint8_t view_pub[32],
                           uint32_t offset,
                           const keyimage_record *recs, size_t nrecs,
                           uint8_t *out_buf, size_t out_cap)
{
    // plaintext = offset(4) || spend_pub(32) || view_pub(32) || N*(ki(32)+sig(64))
    size_t pt_len = 4 + 32 + 32 + nrecs * 96;
    size_t ct_len = pt_len;
    // total = magic(26) || iv(8) || ct(ct_len) || sig(64)
    size_t total = KI_MAGIC_LEN + 8 + ct_len + 64;
    if (total > out_cap) return 0;

    // 1) Собрать plaintext прямо в out_buf (место под ct уже выделено).
    uint8_t *pt_start = out_buf + KI_MAGIC_LEN + 8;
    put_u32_le(pt_start, offset);
    memcpy(pt_start + 4,        spend_pub, 32);
    memcpy(pt_start + 4 + 32,   view_pub,  32);
    for (size_t i = 0; i < nrecs; i++) {
        uint8_t *p = pt_start + 4 + 64 + i * 96;
        memcpy(p,      recs[i].key_image, 32);
        memcpy(p + 32, recs[i].sig_c,     32);
        memcpy(p + 64, recs[i].sig_r,     32);
    }

    // 2) IV (8 байт) — TRNG.
    uint8_t iv[8];
    platform_random_bytes(iv, 8);

    // 3) ChaCha-ключ = cn_slow_hash(view_sk, 32, key, 0, 0, 0).
    uint8_t chacha_key[32];
    cn_slow_hash(view_sk, 32, (char *)chacha_key, 0, 0, 0);

    // 4) Шифрование. IV копируется в out_buf перед ct.
    memcpy(out_buf + KI_MAGIC_LEN, iv, 8);
    // Зашифровываем plaintext НА МЕСТЕ (in == out), читая из pt_start.
    // Внимание: monero_chacha20 пишет XOR в out, поэтому нужен временный буфер.
    uint8_t *ct_out = out_buf + KI_MAGIC_LEN + 8;
    // Сохраним plaintext во временный буфер, чтобы не портить его при XOR на месте.
    uint8_t *pt_tmp = (uint8_t *)malloc(ct_len);
    if (!pt_tmp) { memset(chacha_key, 0, 32); return 0; }
    memcpy(pt_tmp, pt_start, pt_len);

    monero_chacha20(pt_tmp, ct_len, chacha_key, iv, ct_out);
    memset(chacha_key, 0, 32);
    memset(pt_tmp, 0, ct_len);
    free(pt_tmp);

    // 5) Подпись = Schnorr(keccak256(iv || ct), view_pub, view_sk).
    size_t hash_len = 8 + ct_len;
    uint8_t *tmp = (uint8_t *)malloc(hash_len);
    if (!tmp) return 0;
    memcpy(tmp, iv, 8);
    memcpy(tmp + 8, ct_out, ct_len);
    uint8_t hash[32];
    keccak(tmp, hash_len, hash, 32);
    free(tmp);

    uint8_t sig[64];
    if (!crypto_generate_signature(hash, view_pub, view_sk, sig)) return 0;
    memcpy(out_buf + KI_MAGIC_LEN + 8 + ct_len, sig, 64);

    // 6) Magic.
    memcpy(out_buf, KI_MAGIC, KI_MAGIC_LEN);

    return total;
}