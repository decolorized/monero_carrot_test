// CryptoNight v0 для ESP32-S3.
// Изменения:
//   1) local_abort больше не вызывает abort() — только ets_printf.
//   2) В оба горячих цикла добавлен vTaskDelay(1) каждые N итераций,
//      чтобы TWDT/IWDT не сбрасывали чип.
//   3) Диагностика — через ets_printf (не platform_log), чтобы
//      не трогать UART-протокол изнутри тяжёлой функции.
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "int_util_shim.h"
#include "hash-ops.h"
#include "oaes_lib.h"

#include "esp_heap_caps.h"

// Диагностика отключена: USB-порт занят протоколом mwlink, и любой
// посторонний текст в нём ломает кадры COBS.
#define ets_printf(...) ((void)0)

extern void platform_log(const char *msg);

#define MEMORY         (1 << 21)
#define ITER           (1 << 20)
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)

extern void aesb_single_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);
extern void aesb_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);

static void local_abort(const char *msg) {
    platform_log(msg);
}

static void (*const extra_hashes[4])(const void *, size_t, char *) = {
    hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein
};

static size_t e2i(const uint8_t* a, size_t count) {
    return (SWAP64LE(*((uint64_t*)a)) / AES_BLOCK_SIZE) & (count - 1);
}

static void mul(const uint8_t* a, const uint8_t* b, uint8_t* res) {
    uint64_t a0 = SWAP64LE(((uint64_t*)a)[0]);
    uint64_t b0 = SWAP64LE(((uint64_t*)b)[0]);
    uint64_t hi;
    uint64_t lo = mul128(a0, b0, &hi);
    ((uint64_t*)res)[0] = SWAP64LE(hi);
    ((uint64_t*)res)[1] = SWAP64LE(lo);
}

static void sum_half_blocks(uint8_t* a, const uint8_t* b) {
    uint64_t a0 = SWAP64LE(((uint64_t*)a)[0]);
    uint64_t a1 = SWAP64LE(((uint64_t*)a)[1]);
    uint64_t b0 = SWAP64LE(((uint64_t*)b)[0]);
    uint64_t b1 = SWAP64LE(((uint64_t*)b)[1]);
    a0 += b0; a1 += b1;
    ((uint64_t*)a)[0] = SWAP64LE(a0);
    ((uint64_t*)a)[1] = SWAP64LE(a1);
}
#define U64(x) ((uint64_t *)(x))

static void copy_block(uint8_t* dst, const uint8_t* src) {
    memcpy(dst, src, AES_BLOCK_SIZE);
}

static void swap_blocks(uint8_t *a, uint8_t *b) {
    uint64_t t[2];
    U64(t)[0] = U64(a)[0]; U64(t)[1] = U64(a)[1];
    U64(a)[0] = U64(b)[0]; U64(a)[1] = U64(b)[1];
    U64(b)[0] = U64(t)[0]; U64(b)[1] = U64(t)[1];
}

static void xor_blocks(uint8_t* a, const uint8_t* b) {
    for (size_t i = 0; i < AES_BLOCK_SIZE; i++) a[i] ^= b[i];
}

union cn_slow_hash_state {
    union hash_state hs;
    struct {
        uint8_t k[64];
        uint8_t init[INIT_SIZE_BYTE];
    };
};

void cn_slow_hash(const void *data, size_t length, char *hash,
                  int variant, int prehashed, uint64_t height)
{
    (void)variant; (void)prehashed; (void)height;

    ets_printf("[cn_slow_hash] ENTER len=%u psram_free=%u largest=%u\n",
               (unsigned)length,
               (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
               (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM));

    uint8_t *long_state = (uint8_t *)heap_caps_malloc(
        MEMORY, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!long_state) {
        local_abort("cn_slow_hash: no PSRAM for 2MB");
        memset(hash, 0, 32);
        return;
    }
    ets_printf("[cn_slow_hash] long_state=%p\n", long_state);

    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE];
    uint8_t a[AES_BLOCK_SIZE];
    uint8_t a1[AES_BLOCK_SIZE];
    uint8_t b[AES_BLOCK_SIZE * 2];
    uint8_t c1[AES_BLOCK_SIZE];
    uint8_t c2[AES_BLOCK_SIZE];
    uint8_t d[AES_BLOCK_SIZE];
    size_t i, j;
    uint8_t aes_key[AES_KEY_SIZE];
    __attribute__((aligned(16))) uint8_t expandedKey[256];
    oaes_ctx *aes_ctx;

    hash_process(&state.hs, (const uint8_t*)data, length);
    memcpy(text, state.init, INIT_SIZE_BYTE);
    memcpy(aes_key, state.hs.b, AES_KEY_SIZE);

    aes_ctx = (oaes_ctx *) oaes_alloc();
    if (!aes_ctx) {
        local_abort("cn_slow_hash: oaes_alloc NULL");
        heap_caps_free(long_state);
        memset(hash, 0, 32);
        return;
    }
    oaes_key_import_data(aes_ctx, aes_key, AES_KEY_SIZE);
    if (!aes_ctx->key || !aes_ctx->key->exp_data) {
        local_abort("cn_slow_hash: oaes_key_import#1 failed");
        oaes_free((OAES_CTX **) &aes_ctx);
        heap_caps_free(long_state);
        memset(hash, 0, 32);
        return;
    }

    memcpy(expandedKey, aes_ctx->key->exp_data, aes_ctx->key->exp_data_len);

    // ---- Цикл 1: заполнение long_state ----
    for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++)
            aesb_pseudo_round(&text[AES_BLOCK_SIZE * j],
                              &text[AES_BLOCK_SIZE * j], expandedKey);
        memcpy(&long_state[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);

        if ((i & 0x3FF) == 0) vTaskDelay(1);   // каждый 1024-й
    }
    ets_printf("[cn_slow_hash] fill loop done\n");

    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        a[i] = state.k[i] ^ state.k[AES_BLOCK_SIZE * 2 + i];
        b[i] = state.k[AES_BLOCK_SIZE + i] ^ state.k[AES_BLOCK_SIZE * 3 + i];
    }

    // ---- Цикл 2: основной (random-access по PSRAM) ----
    for (i = 0; i < ITER / 2; i++) {
        #define MASK ((uint32_t)(((MEMORY / AES_BLOCK_SIZE) - 1) << 4))
        #define state_index(x) ((*(uint32_t *)(x)) & MASK)

        j = state_index(a);
        uint8_t *p = &long_state[j];
        aesb_single_round(p, c1, a);
        copy_block(p, c1);
        xor_blocks(p, b);

        j = state_index(c1);
        p = &long_state[j];
        copy_block(c2, p);
        copy_block(a1, a);
        mul(c1, c2, d);
        sum_half_blocks(a1, d);
        swap_blocks(a1, c2);
        xor_blocks(a1, c2);
        copy_block(p, c2);
        copy_block(b, c1);
        copy_block(a, a1);

        #undef MASK
        #undef state_index

        if ((i & 0xFFF) == 0) vTaskDelay(1);   // каждый 4096-й
    }
    ets_printf("[cn_slow_hash] main loop done\n");

    memcpy(text, state.init, INIT_SIZE_BYTE);
    oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);
    if (!aes_ctx->key || !aes_ctx->key->exp_data) {
        local_abort("cn_slow_hash: oaes_key_import#2 failed");
        oaes_free((OAES_CTX **) &aes_ctx);
        heap_caps_free(long_state);
        memset(hash, 0, 32);
        return;
    }
    memcpy(expandedKey, aes_ctx->key->exp_data, aes_ctx->key->exp_data_len);

    for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            xor_blocks(&text[j * AES_BLOCK_SIZE],
                       &long_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
            aesb_pseudo_round(&text[AES_BLOCK_SIZE * j],
                              &text[AES_BLOCK_SIZE * j], expandedKey);
        }
        if ((i & 0x3FF) == 0) vTaskDelay(1);
    }

    oaes_free((OAES_CTX **) &aes_ctx);
    memcpy(state.init, text, INIT_SIZE_BYTE);
    hash_permutation(&state.hs);
    extra_hashes[state.hs.b[0] & 3](&state, 200, hash);

    heap_caps_free(long_state);
    ets_printf("[cn_slow_hash] EXIT\n");
}