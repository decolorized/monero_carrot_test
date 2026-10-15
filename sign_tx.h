// sign_tx.h
//
// Публичный интерфейс подписи Monero-транзакции.
//
// Пока реализована только первая стадия: парсинг prefix транзакции
// (version, unlock_time, vin, vout, extra, rct_signatures.base).
// Реальная CLSAG/Bulletproofs+ подпись — TODO.

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Точка входа. Принимает бинарный tx_in (то, что в tx.bin), возвращает
// подписанный tx_out и его длину.
//
// На текущем этапе (stub) просто парсит prefix и возвращает копию
// входных данных. tx_out_len = tx_in_len.
//
// Требования:
//   - tx_out_cap >= tx_in_len (буфер должен вмещать вход).
//   - tx_in_len > 0.
//
// Возвращает true при успехе, false при ошибке парсинга или нехватке
// места в выходном буфере.
bool sign_transaction(const uint8_t *tx_in, size_t tx_in_len,
                      uint8_t *tx_out, size_t tx_out_cap,
                      size_t *tx_out_len);

#ifdef __cplusplus
}
#endif