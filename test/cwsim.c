// cwsim — устройство на ПК: ядро cw_link + подписант, порт — псевдотерминал.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <pty.h>
#include <termios.h>
#include <pthread.h>
#include "cw_link.h"
#include "cw_hotcold.h"
#if __has_include("secrets.h")
#  include "secrets.h"
#else
#  error "secrets.h not found: copy secrets.example.h to secrets.h and put your wallet keys there"
#endif
static int fd;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER, jm = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t jc = PTHREAD_COND_INITIALIZER;
static int jobflag;
static pthread_mutex_t txm = PTHREAD_MUTEX_INITIALIZER;
static uint8_t *hid_out; static size_t hid_out_n;   // для самопроверки HID
static void wr(const uint8_t*d,size_t n){ while(n){ ssize_t w=write(fd,d,n); if(w<=0) return; d+=w; n-=w; } }
void cw_link_send(int tr, const uint8_t *msg, size_t len){
  pthread_mutex_lock(&txm);
  if(tr==CW_TR_HID){ size_t k=cw_link_hid_report_count(len); hid_out=realloc(hid_out,(hid_out_n+k)*63); for(size_t i=0;i<k;i++) cw_link_hid_report(msg,len,i,hid_out+63*(hid_out_n++)); }
  else { size_t cap=len+len/254+8; uint8_t*e=malloc(cap); size_t n=cw_link_serial_frame(msg,len,e,cap); wr(e,n); free(e); }
  pthread_mutex_unlock(&txm);
}
void cw_link_lock(void){ pthread_mutex_lock(&mu); }
void cw_link_unlock(void){ pthread_mutex_unlock(&mu); }
void cw_link_job_signal(void){ pthread_mutex_lock(&jm); jobflag=1; pthread_cond_signal(&jc); pthread_mutex_unlock(&jm); }
void *cw_malloc(size_t n){ return malloc(n); }
void cw_free(void *p){ free(p); }
static void vlog(int lvl,const char*f,va_list a){ char b[300]; vsnprintf(b,sizeof b,f,a); fprintf(stderr,"[dev %d] %s\n",lvl,b); cw_link_log(lvl,b); }
void cw_log(const char*f,...){ va_list a; va_start(a,f); vlog(CW_LOG_INFO,f,a); va_end(a); }
void cw_progress(const char*f,...){ va_list a; va_start(a,f); vlog(CW_LOG_PROGRESS,f,a); va_end(a); }
static cw_input_t store[4096]; static size_t nstore;
bool cw_store_find(const uint8_t O[32], cw_input_t *out){ for(size_t i=0;i<nstore;i++) if(!memcmp(store[i].O,O,32)){*out=store[i];return true;} return false; }
void cw_store_put(const cw_input_t *in){ for(size_t i=0;i<nstore;i++) if(!memcmp(store[i].O,in->O,32)){store[i]=*in;return;} if(nstore<4096) store[nstore++]=*in; }
static cw_wallet_t W;
static void hx(const char*h,uint8_t*o){for(int i=0;i<32;i++)sscanf(h+2*i,"%2hhx",o+i);}
static void *worker(void*a){
  for(;;){
    pthread_mutex_lock(&jm); while(!jobflag) pthread_cond_wait(&jc,&jm); jobflag=0; pthread_mutex_unlock(&jm);
    int kind; uint8_t *d; size_t n;
    while(cw_link_job_take(&kind,&d,&n)){
      uint8_t *out=NULL,*ki=NULL; size_t ol=0,kl=0; char err[200]="";
      bool ok = kind==CW_KIND_UNSIGNED ? cw_sign_unsigned_set2(&W,d,n,&out,&ol,&ki,&kl,err,sizeof err)
                                        : cw_export_key_images(&W,d,n,&out,&ol,err,sizeof err);
      free(d);
      if(ok){ char m[80]; snprintf(m,80,"done: %zu bytes",ol); cw_link_log(CW_LOG_INFO,m); }
      else { char m[260]; snprintf(m,260,"refused: %s",err); cw_link_log(CW_LOG_ERROR,m); fprintf(stderr,"%s\n",m); }
      if(ok && ki) cw_link_job_done2(CW_KIND_SIGNED,out,ol,CW_KIND_KEYIMAGES,ki,kl);
      else cw_link_job_done(kind==CW_KIND_UNSIGNED?CW_KIND_SIGNED:CW_KIND_KEYIMAGES, ok?out:NULL, ol);
    }
  }
  return a;
}
int main(int argc,char**argv){
  uint8_t ks[32],kv[32]; hx(SPEND_SECRET_KEY_HEX,ks); hx(VIEW_SECRET_KEY_HEX,kv);
  if(!cw_wallet_init(&W,ks,kv)) return 1;
  int sfd; char name[64]; struct termios t; cfmakeraw(&t);
  if(openpty(&fd,&sfd,name,&t,NULL)){perror("openpty");return 1;}
  printf("%s\n",name); fflush(stdout);
  if(argc>1){ FILE*f=fopen(argv[1],"w"); fprintf(f,"%s\n",name); fclose(f); }
  cw_link_init(CW_NET_TESTNET,"carrot-0.1","host sim","MoneroCarrot"); cw_link_set_ready(true);
  pthread_t th; pthread_create(&th,NULL,worker,NULL);
  { // самопроверка HID: PING через отчёты, ответ PONG из отчётов
    uint8_t msg[24+300]; const uint8_t mg[8]={0x4D,0x57,0x50,0x4B,0xC7,0x3A,0x5E,0x91};
    memcpy(msg,mg,8); msg[8]=3; msg[9]=1; msg[10]=0; msg[11]=0; uint32_t L=200; memcpy(msg+12,&L,4);
    uint32_t c=cw_crc32(msg,16); memcpy(msg+16,&c,4); for(int i=0;i<200;i++) msg[20+i]=(uint8_t)i; c=cw_crc32(msg,220); memcpy(msg+220,&c,4);
    size_t k=cw_link_hid_report_count(224); uint8_t rep[63];
    for(size_t i=0;i<k;i++){ cw_link_hid_report(msg,224,i,rep); cw_link_feed_hid(rep); }
    uint8_t back[400]; size_t bl=0; for(size_t i=0;i<hid_out_n;i++){ const uint8_t*r=hid_out+63*i; size_t h=i?1:3, t=i?62:60; memcpy(back+bl,r+h,t); bl+=t; }
    int ok = hid_out_n==k && back[9]==0x81 && !memcmp(back+20,msg+20,200);
    fprintf(stderr,"HID self-test: %s (%zu reports)\n", ok?"OK":"FAIL", hid_out_n); hid_out_n=0;
  }
  uint8_t buf[4096];
  for(;;){ ssize_t r=read(fd,buf,sizeof buf); if(r>0) cw_link_feed_serial(buf,r); else usleep(1000); }
}
