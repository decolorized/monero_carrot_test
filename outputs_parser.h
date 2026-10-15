// outputs_parser.h
#ifndef OUTPUTS_PARSER_H
#define OUTPUTS_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Magic файла outputs.bin
#define OUTPUT_MAGIC     "Monero output export\004"
#define MAGIC_LEN        (sizeof(OUTPUT_MAGIC) - 1)   // = 21
#define IV_LEN           8
#define SIG_LEN          64

// Максимальное число записей в outputs.bin
#define OUTPUTS_MAX_RECORDS  64

// Одна запись exported_transfer_details.
// Размер: 32 + 4 + 32 + 4 + 4 = 76 байт (с выравниванием — 80).
typedef struct {
    uint8_t  pubkey[32];        // m_pubkey — output_pubkey (P)
    uint32_t internal_index;    // m_internal_output_index (out_index_in_tx)
    uint8_t  tx_pubkey[32];     // m_tx_pubkey (R)
    uint32_t subaddr_major;
    uint32_t subaddr_minor;
} output_record;

// Результат парсинга outputs.bin.
// records — указатель на массив (выделяется в SRAM через malloc).
typedef struct {
    output_record *records;       // ← указатель, выделяется в SRAM
    uint8_t       *data;          // расшифрованный plaintext (в heap)
    size_t         data_size;     // размер data
    size_t         count;         // сколько записей реально прочитано
} parsed_outputs;

// Парсит outputs.bin.
bool parse_outputs_bin(const uint8_t *in, size_t in_size,
                       const uint8_t view_sk[32],
                       parsed_outputs *out);

// Освобождает records[] и data.
void free_parsed_outputs(parsed_outputs *p);

#ifdef __cplusplus
}
#endif

#endif // OUTPUTS_PARSER_H