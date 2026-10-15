// clsag.h
#ifndef CLSAG_H
#define CLSAG_H

#include <stdint.h>
#include <stdbool.h>

#define CLSAG_MAX_RING 16

typedef struct {
    uint8_t s[CLSAG_MAX_RING][32];
    uint8_t c1[32];
    uint8_t I[32];
    uint8_t D[32];   // УЖЕ умножен на INV_EIGHT
} clsag_t;

bool clsag_prove(const uint8_t message[32],
                 const uint8_t P[][32],
                 const uint8_t C_nonzero[][32],
                 const uint8_t C_offset[32],
                 const uint8_t p[32],
                 const uint8_t z[32],
                 uint32_t l,
                 uint32_t n,
                 clsag_t *out);

#endif // CLSAG_H