#include "epee_reader.h"
#include <string.h>

void epee_init(epee_reader *r, const uint8_t *data, size_t size) {
    r->data = data;
    r->size = size;
    r->pos  = 0;
}

// epee varint: младшие 2 бита первого байта = длина-1 (0,1,2,3 => 1,2,4,8 байт).
bool epee_read_varint(epee_reader *r, uint64_t *out) {
    if (r->pos >= r->size) return false;
    uint8_t b = r->data[r->pos++];
    uint64_t v = b >> 2;
    switch (b & 0x03) {
        case 0: break;
        case 1:
            if (r->pos + 1 > r->size) return false;
            v |= ((uint64_t)r->data[r->pos + 0]) << 6;
            v |= ((uint64_t)r->data[r->pos + 1]) << 14;
            r->pos += 2;
            break;
        case 2:
            if (r->pos + 3 > r->size) return false;
            v |= ((uint64_t)r->data[r->pos + 0]) << 6;
            v |= ((uint64_t)r->data[r->pos + 1]) << 14;
            v |= ((uint64_t)r->data[r->pos + 2]) << 22;
            v |= ((uint64_t)r->data[r->pos + 3]) << 30;
            r->pos += 4;
            break;
        case 3:
            if (r->pos + 7 > r->size) return false;
            v |= ((uint64_t)r->data[r->pos + 0]) << 6;
            v |= ((uint64_t)r->data[r->pos + 1]) << 14;
            v |= ((uint64_t)r->data[r->pos + 2]) << 22;
            v |= ((uint64_t)r->data[r->pos + 3]) << 30;
            v |= ((uint64_t)r->data[r->pos + 4]) << 38;
            v |= ((uint64_t)r->data[r->pos + 5]) << 46;
            v |= ((uint64_t)r->data[r->pos + 6]) << 54;
            v |= ((uint64_t)r->data[r->pos + 7]) << 62;
            r->pos += 8;
            break;
    }
    *out = v;
    return true;
}

bool epee_read_bytes(epee_reader *r, uint8_t *out, size_t n) {
    if (r->pos + n > r->size) return false;
    memcpy(out, r->data + r->pos, n);
    r->pos += n;
    return true;
}

bool epee_skip_bytes(epee_reader *r, size_t n) {
    if (r->pos + n > r->size) return false;
    r->pos += n;
    return true;
}

bool epee_at_end(const epee_reader *r) {
    return r->pos >= r->size;
}

bool epee_read_object_version(epee_reader *r, uint32_t *out_version) {
    uint64_t v;
    if (!epee_read_varint(r, &v)) return false;
    *out_version = (uint32_t)v;
    return true;
}