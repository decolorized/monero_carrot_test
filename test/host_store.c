#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "cw_hotcold.h"
void *cw_malloc(size_t n){ return malloc(n); }
void cw_free(void *p){ free(p); }
static int quiet=0; void set_quiet(int q){quiet=q;}
void cw_log(const char *f, ...){ if(quiet)return; va_list a; va_start(a,f); fprintf(stderr,"  [I] "); vfprintf(stderr,f,a); fprintf(stderr,"\n"); va_end(a);}
void cw_progress(const char *f, ...){ }
static cw_input_t store[4096]; static size_t nstore;
bool cw_store_find(const uint8_t O[32], cw_input_t *out){ for(size_t i=0;i<nstore;i++) if(!memcmp(store[i].O,O,32)){*out=store[i];return true;} return false; }
void cw_store_put(const cw_input_t *in){ for(size_t i=0;i<nstore;i++) if(!memcmp(store[i].O,in->O,32)){store[i]=*in;return;} if(nstore<4096) store[nstore++]=*in; }
void cw_store_clear(void){ nstore=0; }
