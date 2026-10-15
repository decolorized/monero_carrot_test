#pragma once
#include <stddef.h>
static inline void memwipe(void *v, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) *p++ = 0;
}