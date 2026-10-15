#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cw_hotcold.h"
static uint8_t *rf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f){perror(p);exit(2);}fseek(f,0,2);*n=ftell(f);fseek(f,0,0);uint8_t*b=malloc(*n);if(fread(b,1,*n,f)!=*n)exit(2);fclose(f);return b;}
static void hx(const char*h,uint8_t*o){for(int i=0;i<32;i++)sscanf(h+2*i,"%2hhx",o+i);}
int main(int c,char**v){
  if(c<6){fprintf(stderr,"cwtool sign|ki|verify KS KV in out|signed\n");return 2;}
  uint8_t ks[32],kv[32]; hx(v[2],ks); hx(v[3],kv);
  static cw_wallet_t w; if(!cw_wallet_init(&w,ks,kv)){fprintf(stderr,"bad keys\n");return 2;}
  char err[256]=""; size_t n; uint8_t*in=rf(v[4],&n); uint8_t*out; size_t ol;
  if(!strcmp(v[1],"verify")){ size_t m; uint8_t*s=rf(v[5],&m); bool ok=cw_verify_signed_set(&w,in,n,s,m,err,sizeof err); printf("%s %s\n",ok?"OK":"FAIL",err); return !ok; }
  bool ok = !strcmp(v[1],"sign") ? cw_sign_unsigned_set(&w,in,n,&out,&ol,err,sizeof err) : cw_export_key_images(&w,in,n,&out,&ol,err,sizeof err);
  if(!ok){printf("FAIL %s\n",err);return 1;}
  FILE*f=fopen(v[5],"wb"); fwrite(out,1,ol,f); fclose(f); printf("OK %zu\n",ol); return 0;
}
