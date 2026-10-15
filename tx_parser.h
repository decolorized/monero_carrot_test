// tx_parser.h
//
// Парсер raw-транзакции Monero (v1/v2) — то, что приходит из сети.
// НЕ путать с unsigned_tx_set (это отдельный формат, см. unsigned_tx_set.h).

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Разобранный prefix raw-транзакции
// ---------------------------------------------------------------------------
typedef struct {
    uint32_t version;
    uint64_t unlock_time;
    uint32_t vin_count;
    uint32_t vout_count;

    // RingCT
    uint32_t rct_type;
    uint64_t txn_fee;

    // Всё, что нужно для проверки подписи и пересборки
    // (полные структуры добавляются по мере необходимости)
} tx_parsed_t;

// ---------------------------------------------------------------------------
// Разбор prefix (без prunable) raw-транзакции.
// Возвращает true при успехе и позицию сразу после rct_signatures.outPk
// в *pos_after_prefix.
// ---------------------------------------------------------------------------
bool parse_tx_prefix(const uint8_t *tx_in, size_t tx_in_len,
                     tx_parsed_t *out, size_t *pos_after_prefix);

#ifdef __cplusplus
}
#endif