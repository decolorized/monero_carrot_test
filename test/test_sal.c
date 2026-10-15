// test_sal.c — cross-checks SA/L (cw_sal.c) against the monero-oxide Rust
// implementation both ways: Rust verifies our proofs, we verify Rust's.
// fcmp_pp_prove_sal / fcmp_pp_verify_sal come from libfcmp_pp_rust.a of a
// monero fcmp++-beta-stressnet-v3 build:
//   gcc -O2 -Ihost -I.. test_sal.c ../cw_sal.c ../cw_crypto.c ../crypto-ops.c \
//       ../crypto-ops-data.c ../keccak.c ../blake2b.c ../x25519.c platform_host.c \
//       <monero>/build/src/fcmp_pp/fcmp_pp_rust/libfcmp_pp_rust.a -lpthread -ldl -lm -o test_sal
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "cw_crypto.h"
#include "cw_sal.h"
int fcmp_pp_prove_sal(const uint8_t h[32],const uint8_t x[32],const uint8_t y[32],const void*rr,uint8_t proof[384],uint8_t ki[32]);
bool fcmp_pp_verify_sal(const uint8_t h[32],const uint8_t input[128],const uint8_t ki[32],const uint8_t proof[384]);
static void rs(uint8_t s[32]){uint8_t w[64];cw_random(w,64);cw_sc_reduce64(s,w);}
static void hx(const char*l,const uint8_t*b){printf("%s ",l);for(int i=0;i<32;i++)printf("%02x",b[i]);printf("\n");}
int main(){
  int fails=0;
  // generators
  uint8_t h[32],p[32];
  cw_keccak("Monero FCMP++ Generator U",25,h); cw_hp_unbiased(p,h,32); if(memcmp(p,CW_U,32)){printf("U mismatch\n");fails++;}
  cw_keccak("Monero FCMP++ Generator V",25,h); cw_hp_unbiased(p,h,32); if(memcmp(p,CW_V,32)){printf("V mismatch\n");fails++;}
  cw_keccak("Monero Generator T",18,h); cw_hp_unbiased(p,h,32); if(memcmp(p,CW_T,32)){printf("T mismatch\n");fails++;}
  for(int it=0;it<20;it++){
    uint8_t x[32],y[32],O[32],C[32],ro[32],ri[32],rri[32],rc[32],hash[32],m[32];
    rs(x); if(it%3==0) memset(y,0,32); else rs(y); rs(m);
    cw_pt_gt(O,x,y); cw_commit(C,12345+it,m); rs(ro);rs(ri);rs(rri);rs(rc); cw_random(hash,32);
    bool biased = it&1;
    cw_rerand_t rr; if(!cw_rerandomize(&rr,O,C,biased,ro,ri,rri,rc)){printf("rerand fail\n");fails++;continue;}
    uint8_t proof[384],L[32],L2[32],I[32];
    if(!cw_sal_prove(proof,L,hash,&rr,x,y)){printf("prove fail\n");fails++;continue;}
    cw_ki_generator(I,O,biased); cw_pt_mul(L2,x,I); if(memcmp(L,L2,32)){printf("L != xHp(O)\n");fails++;}
    if(!fcmp_pp_verify_sal(hash,(uint8_t*)&rr,L,proof)){printf("RUST rejects my proof (it %d)\n",it);fails++;}
    if(!cw_sal_verify(proof,hash,rr.O_tilde,rr.I_tilde,rr.R,rr.C_tilde,L)){printf("my verify rejects my proof\n");fails++;}
    uint8_t proof2[384],L3[32];
    if(fcmp_pp_prove_sal(hash,x,y,&rr,proof2,L3)){printf("rust prove failed\n");fails++;continue;}
    if(memcmp(L3,L,32)){printf("KI differs from rust\n");fails++;}
    if(!cw_sal_verify(proof2,hash,rr.O_tilde,rr.I_tilde,rr.R,rr.C_tilde,L3)){printf("my verify rejects rust proof\n");fails++;}
    proof[200]^=1; if(cw_sal_verify(proof,hash,rr.O_tilde,rr.I_tilde,rr.R,rr.C_tilde,L)){printf("tampered accepted\n");fails++;}
  }
  // signatures
  uint8_t sk[32],pk[32],sig[64],hh[32]; rs(sk); cw_pt_base(pk,sk); cw_random(hh,32);
  cw_generate_signature(sig,hh,pk,sk); if(!cw_check_signature(sig,hh,pk)){printf("sig fail\n");fails++;}
  uint8_t I[32],L[32]; cw_hp_biased(I,pk); cw_pt_mul(L,sk,I); cw_ring1_signature(sig,L,L,pk,sk); if(!cw_ring1_check(sig,L,L,pk)){printf("ring1 fail\n");fails++;}
  printf("fails=%d\n",fails); return fails!=0;
}
