// main.c — хостовая обвязка: гоняет sign_transaction() из прошивки на ПК.
//
//   make && ./signer ../../tx.bin out.bin [seed]
//
// Кладёт рядом out.bin.uts — расшифрованный unsigned_tx_set (нужен check_tx.py
// для проверки CLSAG: кольцо есть только там).
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "sign_tx.h"
#include "keccak.h"
#include "unsigned_tx_set.h"
#include "secrets.h"
#include "crypto-ops.h"

uint8_t g_spend_secret_key[32];
uint8_t g_view_secret_key[32];
uint8_t g_spend_public_key[32];
uint8_t g_view_public_key[32];

unsigned long millis(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
void platform_log(const char *m) { fprintf(stderr, "[ESP ] %s\n", m); }

// Детерминированный ГПСЧ: одинаковый seed -> одинаковая транзакция.
// Для настоящей подписи на устройстве используется esp_fill_random().
static uint64_t st = 0x243F6A8885A308D3ULL;
void platform_random_bytes(uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        st = st * 6364136223846793005ULL + 1442695040888963407ULL;
        b[i] = (uint8_t)(st >> 33);
    }
}
int ets_printf(const char *fmt, ...) { (void)fmt; return 0; }
size_t heap_caps_get_largest_free_block(int c) { (void)c; return 1u << 20; }
size_t heap_caps_get_free_size(int c) { (void)c; return 1u << 22; }

static int hexb(const char *s, uint8_t *o, int n) {
    for (int i = 0; i < n; i++) { unsigned v; if (sscanf(s + 2*i, "%2x", &v) != 1) return 0; o[i] = v; }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: signer <tx.bin> <out.bin> [seed]\n"); return 2; }
    if (argc > 3) st = strtoull(argv[3], 0, 10);
    if (!hexb(SPEND_SECRET_KEY_HEX, g_spend_secret_key, 32) ||
        !hexb(VIEW_SECRET_KEY_HEX,  g_view_secret_key,  32)) {
        fprintf(stderr, "bad keys in secrets.h\n"); return 2;
    }
    // Публичные ключи — как в setup() прошивки
    { ge_p3 p3;
      ge_scalarmult_base(&p3, g_spend_secret_key); ge_p3_tobytes(g_spend_public_key, &p3);
      ge_scalarmult_base(&p3, g_view_secret_key);  ge_p3_tobytes(g_view_public_key,  &p3); }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *in = malloc(n);
    if (fread(in, 1, n, f) != (size_t)n) { fprintf(stderr, "short read\n"); return 2; }
    fclose(f);

    static uint8_t out[32768]; size_t outlen = 0;
    if (!sign_transaction(in, n, out, sizeof(out), &outlen)) { fprintf(stderr, "SIGN FAILED\n"); return 1; }

    FILE *g = fopen(argv[2], "wb"); fwrite(out, 1, outlen, g); fclose(g);
    fprintf(stderr, "wrote %zu bytes -> %s\n", outlen, argv[2]);

    size_t plen = 0;
    const uint8_t *plain = uts_get_last_plain(&plen);
    if (plain && plen) {
        char path[512]; snprintf(path, sizeof(path), "%s.uts", argv[2]);
        FILE *p = fopen(path, "wb"); fwrite(plain, 1, plen, p); fclose(p);
        fprintf(stderr, "wrote %zu bytes -> %s\n", plen, path);
    }
    return 0;
}
