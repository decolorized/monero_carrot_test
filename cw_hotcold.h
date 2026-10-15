// cw_hotcold.h — файлы обмена горячего и холодного кошелька Monero после
// FCMP++/Carrot (src/wallet/hot_cold.cpp):
//
//   "Monero unsigned tx set" v6  ->  "Monero signed tx set" v6
//   "Monero output export"   v5  ->  "Monero key image export" v4
//
// Устройство разворачивает предложение транзакции из hot_cold_seed,
// само строит Carrot-выходы, считает signable tx hash и ставит SA/L
// на каждый вход. FCMP и Bulletproofs+ достраивает горячий кошелёк.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cw_carrot.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---- платформа -------------------------------------------------------------
void *cw_malloc(size_t n);
void  cw_free(void *p);
void  cw_log(const char *fmt, ...);            // журнал устройства (info)
void  cw_progress(const char *fmt, ...);       // ход работы

// Хранилище открытых входов по одноразовому адресу (переживает перезагрузку).
bool cw_store_find(const uint8_t O[32], cw_input_t *out);
void cw_store_put(const cw_input_t *in);

// ---- контекст кошелька -----------------------------------------------------
typedef struct {
    cw_keys_t keys;
    uint8_t   chacha_key[32];   // cn_slow_hash(k_v): ключ шифрования файлов
    uint64_t  kdf_rounds;       // 1
} cw_wallet_t;

// chacha_key считается здесь (cn_slow_hash, ~2 МБ памяти)
bool cw_wallet_init(cw_wallet_t *w, const uint8_t k_s[32], const uint8_t k_v[32]);

// ---- типы файлов -----------------------------------------------------------
enum {
    CW_FILE_UNKNOWN = -1,
    CW_FILE_OUTPUTS = 0,        // совпадает с KINDS в mwlink.py
    CW_FILE_KEYIMAGES = 1,
    CW_FILE_UNSIGNED = 2,
    CW_FILE_SIGNED = 3,
};
int cw_detect_file(const uint8_t *data, size_t len, int *version_out);

// Результат: *out выделен cw_malloc, освобождать cw_free.
// err — человекочитаемая причина отказа.
bool cw_sign_unsigned_set(const cw_wallet_t *w, const uint8_t *file, size_t len,
                          uint8_t **out, size_t *out_len, char *err, size_t err_len);
// То же + файл "<signed>_keyImages", который monero-wallet-gui ждёт рядом
// с подписанным при отправке (Wallet::submitTxFile).
bool cw_sign_unsigned_set2(const cw_wallet_t *w, const uint8_t *file, size_t len,
                           uint8_t **out, size_t *out_len, uint8_t **ki_out, size_t *ki_len,
                           char *err, size_t err_len);
bool cw_export_key_images(const cw_wallet_t *w, const uint8_t *file, size_t len,
                          uint8_t **out, size_t *out_len, char *err, size_t err_len);

// Расшифровать контейнер (для тестов): plaintext в *out
bool cw_decrypt_file(const cw_wallet_t *w, const uint8_t *file, size_t len,
                     uint8_t **out, size_t *out_len, int *kind, int *version);

// SA/L-проверка подписанного набора против собственного разворота
// неподписанного (для тестов на ПК).
bool cw_verify_signed_set(const cw_wallet_t *w, const uint8_t *unsigned_file, size_t ulen,
                          const uint8_t *signed_file, size_t slen, char *err, size_t err_len);

#ifdef __cplusplus
}
#endif
