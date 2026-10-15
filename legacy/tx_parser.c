// tx_parser.c
//
// Заглушка для raw-транзакций. Реальный парсер prefix — TODO.
// Основной путь сейчас — unsigned_tx_set v5 (см. unsigned_tx_set.c).

#include "tx_parser.h"
#include <string.h>

extern void platform_log(const char *msg);

bool parse_tx_prefix(const uint8_t *tx_in, size_t tx_in_len,
                     tx_parsed_t *out, size_t *pos_after_prefix)
{
    (void)tx_in;
    (void)tx_in_len;

    memset(out, 0, sizeof(*out));

    platform_log("parse_tx_prefix: raw-tx not implemented yet");
    if (pos_after_prefix) *pos_after_prefix = 0;
    return false;
}