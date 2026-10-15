#pragma once
#include <stdint.h>
#include <stddef.h>

// ChaCha20 в точности как crypto::chacha20 в Monero:
// key 32 байта, iv 8 байт (счётчик стартует с 0, nonce = iv).
void monero_chacha20(const uint8_t *data, size_t length,
                     const uint8_t key[32], const uint8_t iv[8],
                     uint8_t *out);