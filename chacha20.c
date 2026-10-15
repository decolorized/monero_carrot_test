#include "chacha20.h"
#include <string.h>

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void chacha_quarter(uint32_t *s, int a, int b, int c, int d) {
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 16);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 12);
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 8);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 7);
}

static void chacha_block(const uint32_t in[16], uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, in, sizeof(x));
    for (int i = 0; i < 10; i++) {
        chacha_quarter(x, 0, 4,  8, 12);
        chacha_quarter(x, 1, 5,  9, 13);
        chacha_quarter(x, 2, 6, 10, 14);
        chacha_quarter(x, 3, 7, 11, 15);
        chacha_quarter(x, 0, 5, 10, 15);
        chacha_quarter(x, 1, 6, 11, 12);
        chacha_quarter(x, 2, 7,  8, 13);
        chacha_quarter(x, 3, 4,  9, 14);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + in[i];
        out[i*4 + 0] = (uint8_t)(v);
        out[i*4 + 1] = (uint8_t)(v >> 8);
        out[i*4 + 2] = (uint8_t)(v >> 16);
        out[i*4 + 3] = (uint8_t)(v >> 24);
    }
}

void monero_chacha20(const uint8_t *data, size_t length,
                     const uint8_t key[32], const uint8_t iv[8],
                     uint8_t *out)
{
    uint32_t state[16];
    // "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) {
        state[4 + i] = (uint32_t)key[i*4]        |
                       ((uint32_t)key[i*4 + 1] << 8)  |
                       ((uint32_t)key[i*4 + 2] << 16) |
                       ((uint32_t)key[i*4 + 3] << 24);
    }
    // Monero использует 8-байтовый IV, который занимает позиции 14,15 (counter=12,13=0)
    // Однако: в crypto::chacha20 Monero работает c 64-битным счётчиком.
    // Формат: state[12], state[13] = counter (0 на старте), state[14], state[15] = IV.
    state[12] = 0;
    state[13] = 0;
    state[14] = (uint32_t)iv[0]        |
                ((uint32_t)iv[1] << 8)  |
                ((uint32_t)iv[2] << 16) |
                ((uint32_t)iv[3] << 24);
    state[15] = (uint32_t)iv[4]        |
                ((uint32_t)iv[5] << 8)  |
                ((uint32_t)iv[6] << 16) |
                ((uint32_t)iv[7] << 24);

    uint8_t keystream[64];
    size_t off = 0;
    while (off < length) {
        chacha_block(state, keystream);
        // инкремент 64-битного счётчика (state[12] = low, state[13] = high)
        if (++state[12] == 0) ++state[13];

        size_t chunk = length - off;
        if (chunk > 64) chunk = 64;
        for (size_t i = 0; i < chunk; i++) {
            out[off + i] = data[off + i] ^ keystream[i];
        }
        off += chunk;
    }
}