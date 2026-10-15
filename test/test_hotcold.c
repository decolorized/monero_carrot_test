#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secrets.h"
#include "cw_hotcold.h"
#include "cw_crypto.h"
void cw_store_clear(void);
static uint8_t *rf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f){perror(p);exit(1);}fseek(f,0,2);*n=ftell(f);fseek(f,0,0);uint8_t*b=malloc(*n);fread(b,1,*n,f);fclose(f);return b;}
static void hx(const char*h,uint8_t*o){for(int i=0;i<32;i++)sscanf(h+2*i,"%2hhx",o+i);}
int main(int argc,char**argv){
  uint8_t ks[32],kv[32]; hx(SPEND_SECRET_KEY_HEX,ks); hx(VIEW_SECRET_KEY_HEX,kv);
  static cw_wallet_t w; if(!cw_wallet_init(&w,ks,kv)){printf("bad keys\n");return 1;}
  char err[200]; int fails=0; const char*V="../../gui/";
  cw_store_clear();
  { size_t n; uint8_t*o=rf("../../gui/o",&n); uint8_t*out; size_t ol;
    if(!cw_export_key_images(&w,o,n,&out,&ol,err,sizeof err)){printf("KI export FAIL: %s\n",err);fails++;}
    else { printf("key images: %zu bytes (GUI k %d)\n",ol,1002); FILE*f=fopen("out_keyImages","wb"); fwrite(out,1,ol,f); fclose(f);} }
  const char *pairs[][2]={{"tx1","tx1_signed"},{"tx2","tx2_signed"}};
  for(int i=0;i<2;i++){
    char a[256],b[256]; snprintf(a,256,"%s%s",V,pairs[i][0]); snprintf(b,256,"%s%s",V,pairs[i][1]);
    size_t ul,sl; uint8_t*u=rf(a,&ul),*s=rf(b,&sl);
    if(cw_verify_signed_set(&w,u,ul,s,sl,err,sizeof err)) printf("GUI %s: our expansion verifies GUI SA/L proofs: OK\n",pairs[i][1]);
    else {printf("GUI %s: FAIL %s\n",pairs[i][1],err);fails++;}
    uint8_t*out; size_t ol;
    if(!cw_sign_unsigned_set(&w,u,ul,&out,&ol,err,sizeof err)){printf("sign %s FAIL: %s\n",pairs[i][0],err);fails++;continue;}
    printf("signed %s: %zu bytes (GUI %zu)\n",pairs[i][0],ol,sl);
    if(cw_verify_signed_set(&w,u,ul,out,ol,err,sizeof err)) printf("  own signature verifies: OK\n"); else {printf("  own verify FAIL %s\n",err);fails++;}
    char o[256]; snprintf(o,256,"out_%s_signed",pairs[i][0]); FILE*f=fopen(o,"wb"); fwrite(out,1,ol,f); fclose(f);
  }
  printf("fails=%d\n",fails); return fails;
}
