// Замена <sodium/crypto_verify_32.h> - libsodium на ESP32/Arduino не
// подключаем. Семантика идентична оригиналу: 0 если равны, -1 иначе.
// Используется в crypto-ops.c только в fe_equals() (в нашем сценарии
// не вызывается на пути derive_and_sign_key_image, но должен быть
// определён для компоновки объектного файла).
#pragma once
#include <stdint.h>

static inline int crypto_verify_32(const unsigned char *x, const unsigned char *y) {
    unsigned char diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= (unsigned char)(x[i] ^ y[i]);
    }
    return diff == 0 ? 0 : -1;
}
