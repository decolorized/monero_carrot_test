// unsigned_tx_set.h
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define UTS_MAX_TXES                 4
#define UTS_MAX_SOURCES              8
#define UTS_MAX_RING_SIZE            32
#define UTS_MAX_DESTS                16
#define UTS_MAX_SELECTED             64
#define UTS_MAX_EXTRA                256
#define UTS_MAX_ORIGINAL_LEN         128
#define UTS_MAX_SUBADDR_INDICES      16
#define UTS_MAX_ADDITIONAL_TX_KEYS   16   // ← НОВОЕ

typedef struct {
    uint8_t dest[32];
    uint8_t mask[32];
} uts_ctkey_t;

typedef struct {
    uint8_t  spend_public_key[32];
    uint8_t  view_public_key[32];
} uts_account_public_address_t;

typedef struct {
    uint64_t global_index;      // ← varint в файле
    uts_ctkey_t ctkey;          // 64 байта: dest(32) + mask(32)
} uts_tx_source_output_t;

typedef struct {
    uint32_t n_outputs;
    uts_tx_source_output_t outputs[UTS_MAX_RING_SIZE];

    uint64_t real_output;                      // 8 байт LE (FIELD)
    uint8_t  real_out_tx_key[32];              // 32 байта

    // ← НОВОЕ: vector<public_key> additional_tx_keys
    uint32_t n_additional_tx_keys;             // varint
    uint8_t  additional_tx_keys[UTS_MAX_ADDITIONAL_TX_KEYS][32];

    uint64_t real_output_in_tx_index;          // 8 байт LE (FIELD)
    uint64_t amount;                           // 8 байт LE (FIELD)
    bool     rct;                              // 1 байт
    uint8_t  mask[32];                         // 32 байта
    uint8_t  multisig_kLRki[128];              // 128 байт
} uts_tx_source_entry_t;

typedef struct {
    uint32_t original_len;
    char     original[UTS_MAX_ORIGINAL_LEN + 1];
    uint64_t amount;
    uts_account_public_address_t addr;
    bool     is_subaddress;
    bool     is_integrated;
} uts_tx_destination_entry_t;

typedef struct {
    uint32_t n_sources;
    uts_tx_source_entry_t sources[UTS_MAX_SOURCES];

    uts_tx_destination_entry_t change_dts;

    uint32_t n_splitted_dsts;
    uts_tx_destination_entry_t splitted_dsts[UTS_MAX_DESTS];

    uint32_t n_selected_transfers;
    uint64_t selected_transfers[UTS_MAX_SELECTED];

    uint32_t extra_len;
    uint8_t  extra[UTS_MAX_EXTRA];

    uint64_t unlock_time;                      // 8 байт LE
    uint8_t  construction_flags;               // 1 байт: бит0=use_rct, бит1=use_view_tags
    bool     use_rct;
    bool     use_view_tags;

    uint32_t rct_config_type;
    uint32_t rct_config_bp;

    uint32_t n_dests;
    uts_tx_destination_entry_t dests[UTS_MAX_DESTS];

    uint32_t subaddr_account;
    uint32_t n_subaddr_indices;
    uint32_t subaddr_indices[UTS_MAX_SUBADDR_INDICES];
} uts_tx_construction_data_t;

typedef struct {
    uint32_t n_txes;
    uts_tx_construction_data_t txes[UTS_MAX_TXES];
} unsigned_tx_set_t;

bool uts_parse_plain(const uint8_t *in, size_t in_len, unsigned_tx_set_t *out);
bool uts_parse_encrypted(const uint8_t *in, size_t in_len,
                         const uint8_t view_sk[32],
                         unsigned_tx_set_t *out);
void uts_dump(const unsigned_tx_set_t *s);
void uts_set_last_plain(uint8_t *p, size_t n);
const uint8_t *uts_get_last_plain(size_t *out_len);