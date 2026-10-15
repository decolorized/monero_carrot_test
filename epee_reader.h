#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    const uint8_t *data;
    size_t         size;
    size_t         pos;
} epee_reader;

void     epee_init(epee_reader *r, const uint8_t *data, size_t size);
bool     epee_read_varint(epee_reader *r, uint64_t *out);
bool     epee_read_bytes(epee_reader *r, uint8_t *out, size_t n);
bool     epee_skip_bytes(epee_reader *r, size_t n);
bool     epee_at_end(const epee_reader *r);

// Удобная обёртка "прочитать элемент с version-полем" (см. BEGIN_SERIALIZE_OBJECT с VERSION_FIELD).
// В epee version сериализуется как varint, а не как "отдельное поле".
bool     epee_read_object_version(epee_reader *r, uint32_t *out_version);