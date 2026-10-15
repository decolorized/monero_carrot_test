#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
void cw_random(uint8_t *b, size_t n){ FILE*f=fopen("/dev/urandom","rb"); fread(b,1,n,f); fclose(f); }
void platform_log(const char *m){ fprintf(stderr,"[dev] %s\n",m); }
int ets_printf(const char*f,...){return 0;}
size_t heap_caps_get_largest_free_block(int c){return 1u<<22;}
size_t heap_caps_get_free_size(int c){return 1u<<22;}
unsigned long millis(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000+t.tv_nsec/1000000;}
