#pragma once
#include <stdlib.h>
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define MALLOC_CAP_INTERNAL 4
static inline void *heap_caps_malloc(size_t s, int caps){ (void)caps; return malloc(s); }
static inline void heap_caps_free(void*p){ free(p); }
