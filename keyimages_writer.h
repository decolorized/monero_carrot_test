#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t key_image[32];
    uint8_t sig_c[32];
    uint8_t sig_r[32];
} keyimage_record;

// Собирает keyimages.bin в out_buf.
// Возвращает длину получившегося файла или 0 при ошибке.
size_t build_keyimages_bin(const uint8_t view_sk[32],
                           const uint8_t spend_pub[32],
                           const uint8_t view_pub[32],
                           uint32_t offset,
                           const keyimage_record *recs, size_t nrecs,
                           uint8_t *out_buf, size_t out_cap);

#ifdef __cplusplus
}
#endif