// sign_tx_construct.h
// Построение prefix транзакции Monero из unsigned_tx_set.
// Плюс экспорт приватных ключей источников (x) для CLSAG.
// Плюс экспорт ОТСОРТИРОВАННЫХ источников для CLSAG.

#ifndef SIGN_TX_CONSTRUCT_H
#define SIGN_TX_CONSTRUCT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "unsigned_tx_set.h"

// Установить raw plaintext
void sign_set_raw_plain(const uint8_t *raw, size_t len);

// Построить prefix транзакции и посчитать prefix_hash.
// Возвращает длину prefix в байтах (0 при ошибке).
size_t sign_build_prefix(const unsigned_tx_set_t *uts,
                         const uint8_t tx_secret_key[32],
                         const uint8_t *additional_tx_keys,
                         uint32_t n_additional_tx_keys,
                         uint8_t *out_buf, size_t out_cap,
                         uint8_t prefix_hash_out[32]);

// ===========================================================================
// Экспорт приватных ключей источников
// x = Hs(deriv || varint(idx)) + spend_sk [+ m_sub]
// ===========================================================================

// Получить x для источника s (0..n_sources-1).
bool sign_get_source_x(uint32_t s, uint8_t x_out[32]);

// Получить key image для источника s.
bool sign_get_source_ki(uint32_t s, uint8_t ki_out[32]);

// ===========================================================================
// Экспорт ОТСОРТИРОВАННЫХ источников (для CLSAG)
// ===========================================================================

// Получить отсортированный источник s.
// Кольца отсортированы по global_index (как в sign_build_prefix).
// real_output уже пересчитан под отсортированный порядок.
bool sign_get_sorted_source(uint32_t s, uts_tx_source_entry_t *out);

// Сколько источников доступно.
uint32_t sign_get_n_sources(void);

// ===========================================================================
// Классификация адресов назначения (порт cryptonote::classify_addresses)
// ===========================================================================

// true, если этот получатель — сдача на собственный обычный адрес.
bool sign_dst_is_change(const uts_tx_construction_data_t *tx,
                        const uts_tx_destination_entry_t *d);

// use_subaddr = (num_std == 0 && num_sub == 1)   (адрес сдачи исключён!)
// need_additional = num_sub > 0 && (num_std > 0 || num_sub > 1)
bool sign_classify_dsts(const uts_tx_construction_data_t *tx,
                        bool *use_subaddr_out,
                        uint8_t single_sub_spend_pub[32],
                        bool *need_additional_out);

// ===========================================================================
// Per-output derivations, посчитанные в sign_build_prefix.
// rct-часть ОБЯЗАНА брать их отсюда, а не считать заново: при
// need_additional_txkeys у субадресных выходов свой секрет r_i.
// ===========================================================================
bool sign_get_output_derivation(uint32_t i, uint8_t deriv_out[32]);
uint32_t sign_get_n_output_derivations(void);

#endif // SIGN_TX_CONSTRUCT_H