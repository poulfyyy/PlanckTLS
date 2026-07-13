#include "planck.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#ifndef PLANCK_DEBUG
#define PLANCK_DEBUG 0
#endif
#if PLANCK_DEBUG
#define LOG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define LOG(fmt, ...) ((void)0)
#endif
#define TLS_HS_CLIENT_HELLO          1
#define TLS_HS_SERVER_HELLO          2
#define TLS_HS_ENCRYPTED_EXTENSIONS  8
#define TLS_HS_CERTIFICATE          11
#define TLS_HS_CERTIFICATE_VERIFY   15
#define TLS_HS_SERVER_KEY_EXCHANGE  12
#define TLS_HS_SERVER_HELLO_DONE    14
#define TLS_HS_CLIENT_KEY_EXCHANGE  16
#define TLS_HS_FINISHED             20
#define TLS_CONTENT_HANDSHAKE       22
#define TLS_CONTENT_APP_DATA        23
#define TLS_CONTENT_CHANGE_CIPHER   20
#define TLS_CONTENT_ALERT           21
#define TLS_EXT_SNI                 0
#define TLS_EXT_SUPPORTED_GROUPS   10
#define TLS_EXT_KEY_SHARE          51
#define TLS_EXT_SUPPORTED_VERSIONS 43
#define TLS_EXT_PSK_KEY_EXCHANGE   45
#define TLS_EXT_SIGNATURE_ALGOS    13
#define TLS_EXT_ALPN               16
#define MAX_BUF                    32768
#define AES_GCM_KEY_SIZE           16
#define AES_GCM_IV_SIZE            12
#define AES_GCM_TAG_SIZE           16
#define CHACHA_KEY_SIZE            32
#define CHACHA_IV_SIZE             12
#define SHA256_SIZE                32
typedef int64_t fe[5];
#define LMASK 0x7ffffffffffffULL
#define LBITS 51
static uint64_t load64(const uint8_t *p){
    return (uint64_t)p[0]|(uint64_t)p[1]<<8|(uint64_t)p[2]<<16|(uint64_t)p[3]<<24
          |(uint64_t)p[4]<<32|(uint64_t)p[5]<<40|(uint64_t)p[6]<<48|(uint64_t)p[7]<<56;
}
static void fexpand(fe o,const uint8_t *in){
    uint8_t buf[39];memcpy(buf,in,32);memset(buf+32,0,7);
    o[0]=(int64_t)(load64(buf+0)&LMASK);
    o[1]=(int64_t)((load64(buf+6)>>3)&LMASK);
    o[2]=(int64_t)((load64(buf+12)>>6)&LMASK);
    o[3]=(int64_t)((load64(buf+19)>>1)&LMASK);
    o[4]=(int64_t)((load64(buf+25)>>4)&LMASK);
}
static void fcontract(uint8_t *out,fe h){
    int i; __int128 t;
    for(i=0;i<2;i++){
        for(int j=0;j<4;j++){ t=h[j]; h[j+1]+=t>>51; h[j]=t-((t>>51)<<51); }
        t=h[4]; h[0]+=(t>>51)*19; h[4]=t-((t>>51)<<51);
        for(int j=0;j<4;j++){ t=h[j]; h[j+1]+=t>>51; h[j]=t-((t>>51)<<51); }
        t=h[4]; h[0]+=(t>>51)*19; h[4]=t-((t>>51)<<51);
    }
    for(i=0;i<4;i++){ if(h[i]<0){ h[i]+=(1LL<<51); h[i+1]--; } }
    if(h[4]<0){ h[0]+=19*(1LL<<51); h[4]+=(1LL<<51); }
    if(h[0]<0) h[0]+=(1LL<<51); 
    if((h[4]&LMASK)==LMASK && (h[3]&LMASK)==LMASK && (h[2]&LMASK)==LMASK && (h[1]&LMASK)==LMASK && h[0]>=LMASK-18){
        h[0]-=LMASK-18; h[1]=0; h[2]=0; h[3]=0; h[4]=0;
    }
    uint64_t a0=h[0],a1=h[1],a2=h[2],a3=h[3],a4=h[4];
    out[0]=a0;out[1]=a0>>8;out[2]=a0>>16;out[3]=a0>>24;
    out[4]=a0>>32;out[5]=a0>>40;out[6]=a0>>48;
    out[6]|=a1<<3;out[7]=a1>>5;out[8]=a1>>13;out[9]=a1>>21;
    out[10]=a1>>29;out[11]=a1>>37;out[12]=a1>>45;
    out[12]|=a2<<6;out[13]=a2>>2;out[14]=a2>>10;out[15]=a2>>18;
    out[16]=a2>>26;out[17]=a2>>34;out[18]=a2>>42;out[19]=a2>>50;
    out[19]|=a3<<1;out[20]=a3>>7;out[21]=a3>>15;out[22]=a3>>23;
    out[23]=a3>>31;out[24]=a3>>39;out[25]=a3>>47;
    out[25]|=a4<<4;out[26]=a4>>4;out[27]=a4>>12;out[28]=a4>>20;
    out[29]=a4>>28;out[30]=a4>>36;out[31]=a4>>44;
}
static void fsum(fe o,const fe a,const fe b){int i;for(i=0;i<5;i++)o[i]=a[i]+b[i];}
static void fdifference(fe o,const fe a,const fe b){int i;for(i=0;i<5;i++)o[i]=a[i]-b[i];}
static void fmul(fe o,const fe a,const fe b){
    __int128 r[9]={0};int i,j;
    for(i=0;i<5;i++)for(j=0;j<5;j++)r[i+j]+=(__int128)a[i]*b[j];
    for(i=0;i<8;i++){ __int128 c=r[i]>>51; r[i+1]+=c; r[i]-=c<<51; }
    r[0]+=r[5]*19; r[1]+=r[6]*19; r[2]+=r[7]*19; r[3]+=r[8]*19;
    for(i=0;i<2;i++){
        for(j=0;j<4;j++){ __int128 c=r[j]>>51; r[j+1]+=c; r[j]-=c<<51; }
        { __int128 c=r[4]>>51; r[0]+=c*19; r[4]-=c<<51; }
    }
    for(i=0;i<5;i++)o[i]=(int64_t)r[i];
}
static void fsquare(fe o,const fe a){fmul(o,a,a);}
static void fmul121666(fe o,const fe a){
    __int128 r[5];int i;
    for(i=0;i<5;i++)r[i]=(__int128)a[i]*121666;
    for(i=0;i<2;i++){
        for(int j=0;j<4;j++){ __int128 c=r[j]>>51; r[j+1]+=c; r[j]-=c<<51; }
        { __int128 c=r[4]>>51; r[0]+=c*19; r[4]-=c<<51; }
        for(int j=0;j<4;j++){ __int128 c=r[j]>>51; r[j+1]+=c; r[j]-=c<<51; }
        { __int128 c=r[4]>>51; r[0]+=c*19; r[4]-=c<<51; }
    }
    for(i=0;i<5;i++)o[i]=(int64_t)r[i];
}
static void finvert(fe o,const fe a){
    fe t0,t1,t2,t3;int i;
    fmul(t0,a,a);         fsquare(t1,t0);       
    fsquare(t1,t1);       fmul(t1,a,t1);        
    fmul(t0,t0,t1);       fsquare(t2,t0);       
    fmul(t1,t1,t2);       fsquare(t2,t1);       
    for(i=1;i<5;i++)fsquare(t2,t2);  fmul(t1,t2,t1);  
    fsquare(t2,t1);       for(i=1;i<10;i++)fsquare(t2,t2);
    fmul(t2,t2,t1);       fsquare(t3,t2);
    for(i=1;i<20;i++)fsquare(t3,t3); fmul(t2,t3,t2);    
    fsquare(t2,t2);      for(i=1;i<10;i++)fsquare(t2,t2);
    fmul(t1,t2,t1);       fsquare(t2,t1);
    for(i=1;i<50;i++)fsquare(t2,t2); fmul(t2,t2,t1);    
    fsquare(t3,t2);      for(i=1;i<100;i++)fsquare(t3,t3);
    fmul(t2,t3,t2);       fsquare(t2,t2);
    for(i=1;i<50;i++)fsquare(t2,t2); fmul(t1,t2,t1);    
    fsquare(t1,t1);      
    for(i=1;i<5;i++)fsquare(t1,t1); 
    fmul(o,t1,t0);       
}
static void fselect(fe a,fe b,uint64_t swap){
    uint64_t m=-swap;int i;for(i=0;i<5;i++){uint64_t t=m&((uint64_t)a[i]^(uint64_t)b[i]);a[i]^=(int64_t)t;b[i]^=(int64_t)t;}
}
static void x25519_scalar_mult(uint8_t out[32],const uint8_t scalar[32],const uint8_t point[32]){
    fe x1,x2={1},z2={0},x3,z3={1},a,aa,b,bb,c,d,da,cb,e;
    uint8_t clamped[32];memcpy(clamped,scalar,32);clamped[0]&=248;clamped[31]&=127;clamped[31]|=64;
    fexpand(x1,point);fexpand(x3,point);
    uint64_t swap=0;int i;
    for(i=254;i>=0;i--){
        uint64_t bit=(clamped[i>>3]>>(i&7))&1,k=bit^swap;swap=bit;
        fselect(x2,x3,k);fselect(z2,z3,k);
        fsum(a,x2,z2);fsquare(aa,a);
        fdifference(b,x2,z2);fsquare(bb,b);
        fdifference(e,aa,bb);
        fsum(c,x3,z3);fdifference(d,x3,z3);
        fmul(da,d,a);fmul(cb,c,b);
        fsum(a,da,cb);fsquare(x3,a);
        fdifference(b,da,cb);fsquare(c,b);
        fmul(z3,x1,c);
        fmul(x2,aa,bb);
        fmul121666(c,e);fsum(b,c,bb);
        fmul(z2,e,b);
#if PLANCK_DEBUG
        if(i==254||i==253){
            fprintf(stderr,"i=%d bit=%lu x2=%016lx %016lx %016lx %016lx %016lx z2=%016lx %016lx %016lx %016lx %016lx\n",
                i,(unsigned long)bit,
                (unsigned long)(x2[0]&0x7ffffffffffffULL),(unsigned long)(x2[1]&0x7ffffffffffffULL),(unsigned long)(x2[2]&0x7ffffffffffffULL),(unsigned long)(x2[3]&0x7ffffffffffffULL),(unsigned long)(x2[4]&0x7ffffffffffffULL),
                (unsigned long)(z2[0]&0x7ffffffffffffULL),(unsigned long)(z2[1]&0x7ffffffffffffULL),(unsigned long)(z2[2]&0x7ffffffffffffULL),(unsigned long)(z2[3]&0x7ffffffffffffULL),(unsigned long)(z2[4]&0x7ffffffffffffULL));
            fprintf(stderr,"i=%d bit=%lu x3=%016lx %016lx %016lx %016lx %016lx z3=%016lx %016lx %016lx %016lx %016lx\n",
                i,(unsigned long)bit,
                (unsigned long)(x3[0]&0x7ffffffffffffULL),(unsigned long)(x3[1]&0x7ffffffffffffULL),(unsigned long)(x3[2]&0x7ffffffffffffULL),(unsigned long)(x3[3]&0x7ffffffffffffULL),(unsigned long)(x3[4]&0x7ffffffffffffULL),
                (unsigned long)(z3[0]&0x7ffffffffffffULL),(unsigned long)(z3[1]&0x7ffffffffffffULL),(unsigned long)(z3[2]&0x7ffffffffffffULL),(unsigned long)(z3[3]&0x7ffffffffffffULL),(unsigned long)(z3[4]&0x7ffffffffffffULL));
        }
#endif
    }
    fselect(x2,x3,swap);fselect(z2,z3,swap);
    finvert(a,z2);fmul(b,x2,a);fcontract(out,b);
}
static void x25519_keygen(uint8_t pub[32],const uint8_t priv[32]){
    uint8_t base[32]={9};x25519_scalar_mult(pub,priv,base);
}
static const uint32_t sha256_k[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
typedef struct{uint32_t s[8];uint64_t len;uint8_t b[64];int off;}sha256_ctx;
static uint32_t sha256_rotr(uint32_t x,int n){return(x>>n)|(x<<(32-n));}
static void sha256_transform(uint32_t s[8],const uint8_t b[64]){
    uint32_t w[64],a=s[0],B=s[1],C=s[2],D=s[3],e=s[4],f=s[5],g=s[6],h=s[7];int i;
    for(i=0;i<16;i++)w[i]=((uint32_t)b[i*4]<<24)|((uint32_t)b[i*4+1]<<16)|((uint32_t)b[i*4+2]<<8)|b[i*4+3];
    for(i=16;i<64;i++){
        uint32_t s0=sha256_rotr(w[i-15],7)^sha256_rotr(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=sha256_rotr(w[i-2],17)^sha256_rotr(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    for(i=0;i<64;i++){
        uint32_t S1=sha256_rotr(e,6)^sha256_rotr(e,11)^sha256_rotr(e,25);
        uint32_t ch=(e&f)^((~e)&g),t1=h+S1+ch+sha256_k[i]+w[i];
        uint32_t S0=sha256_rotr(a,2)^sha256_rotr(a,13)^sha256_rotr(a,22);
        uint32_t maj=(a&B)^(a&C)^(B&C),t2=S0+maj;
        h=g;g=f;f=e;e=D+t1;D=C;C=B;B=a;a=t1+t2;
    }
    s[0]+=a;s[1]+=B;s[2]+=C;s[3]+=D;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
static void sha256_init(sha256_ctx*ctx){
    ctx->s[0]=0x6a09e667;ctx->s[1]=0xbb67ae85;ctx->s[2]=0x3c6ef372;ctx->s[3]=0xa54ff53a;
    ctx->s[4]=0x510e527f;ctx->s[5]=0x9b05688c;ctx->s[6]=0x1f83d9ab;ctx->s[7]=0x5be0cd19;
    ctx->len=0;ctx->off=0;
}
static void sha256_update(sha256_ctx*ctx,const uint8_t*d,size_t l){
    ctx->len+=l*8;
    while(l>0){
        size_t space=64-ctx->off,take=l<space?l:space;
        memcpy(ctx->b+ctx->off,d,take);d+=take;l-=take;ctx->off+=take;
        if(ctx->off==64){sha256_transform(ctx->s,ctx->b);ctx->off=0;}
    }
}
static void sha256_final(uint8_t out[32],sha256_ctx*ctx){
    uint64_t bl=ctx->len; 
    uint8_t pad[64];int i;memset(pad,0,64);pad[0]=0x80;sha256_update(ctx,pad,1);
    while(ctx->off!=56){pad[0]=0;sha256_update(ctx,pad,1);}
    for(i=7;i>=0;i--)pad[i]=(bl>>(56-i*8))&0xff;
    sha256_update(ctx,pad,8);
    for(i=0;i<8;i++){
        out[i*4]=(ctx->s[i]>>24)&0xff;out[i*4+1]=(ctx->s[i]>>16)&0xff;
        out[i*4+2]=(ctx->s[i]>>8)&0xff;out[i*4+3]=ctx->s[i]&0xff;
    }
}
static void hmac_sha256(uint8_t out[32],const uint8_t*k,size_t kl,const uint8_t*d,size_t dl){
    uint8_t kb[64],ik[64],ok[64],ih[32];sha256_ctx ctx;int i;
    memset(kb,0,64);
    if(kl>64){sha256_init(&ctx);sha256_update(&ctx,k,kl);sha256_final(kb,&ctx);}
    else memcpy(kb,k,kl);
    for(i=0;i<64;i++){ik[i]=kb[i]^0x36;ok[i]=kb[i]^0x5c;}
    sha256_init(&ctx);sha256_update(&ctx,ik,64);sha256_update(&ctx,d,dl);sha256_final(ih,&ctx);
    sha256_init(&ctx);sha256_update(&ctx,ok,64);sha256_update(&ctx,ih,32);sha256_final(out,&ctx);
}
static void hkdf_extract(uint8_t prk[32],const uint8_t*salt,size_t sl,const uint8_t*ikm,size_t il){
    uint8_t z[32]={0};hmac_sha256(prk,salt?salt:z,salt?sl:32,ikm,il);
}
static void hkdf_expand_label(uint8_t *okm, size_t ol,
                              const uint8_t prk[32],
                              const char *label,
                              const uint8_t *ctx, size_t cl)
{
    uint8_t info[256];
    int il = 0;
    info[il++] = (uint8_t)(ol >> 8);
    info[il++] = (uint8_t)(ol);
    int ll = (int)strlen(label);
    info[il++] = (uint8_t)(6 + ll);
    memcpy(info + il, "tls13 ", 6);
    il += 6;
    memcpy(info + il, label, ll);
    il += ll;
    info[il++] = (uint8_t)cl;
    if (cl) {
        memcpy(info + il, ctx, cl);
        il += (int)cl;
    }
    uint8_t t[32];
    size_t tlen = 0;
    size_t off = 0;
    uint8_t counter = 1;
    while (off < ol) {
        uint8_t buf[512];
        int bl = 0;
        if (tlen) {
            memcpy(buf, t, tlen);
            bl = (int)tlen;
        }
        memcpy(buf + bl, info, il);
        bl += il;
        buf[bl++] = counter;
        hmac_sha256(t, prk, 32, buf, bl);
        tlen = 32;
        size_t n = ol - off;
        if (n > sizeof(t))
            n = sizeof(t);
        memcpy(okm + off, t, n);
        off += n;
        counter++;
    }
}
static void tls12_prf_sha256(uint8_t *out, size_t olen,
                              const uint8_t *secret, size_t slen,
                              const char *label,
                              const uint8_t *seed, size_t seedlen) {
    uint8_t full_seed[256];
    size_t ll = strlen(label);
    memcpy(full_seed, label, ll);
    memcpy(full_seed + ll, seed, seedlen);
    size_t fsl = ll + seedlen;
    uint8_t A[32];
    hmac_sha256(A, secret, slen, full_seed, fsl);
    size_t off = 0;
    while (off < olen) {
        uint8_t buf[32 + 256];
        memcpy(buf, A, 32);
        memcpy(buf + 32, full_seed, fsl);
        hmac_sha256(A, secret, slen, A, 32);
        uint8_t block[32];
        hmac_sha256(block, secret, slen, buf, 32 + fsl);
        size_t n = olen - off;
        if (n > 32) n = 32;
        memcpy(out + off, block, n);
        off += n;
    }
}
static const uint8_t aes_sbox[256]={
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static const uint32_t aes_rcon[10]={
0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000};
static uint32_t aes_subw(uint32_t w){
    return(aes_sbox[w>>24]<<24)|(aes_sbox[(w>>16)&0xff]<<16)|
          (aes_sbox[(w>>8)&0xff]<<8)|aes_sbox[w&0xff];
}
static uint32_t aes_rotw(uint32_t w){return(w<<8)|(w>>24);}
static void aes_key_expand(uint32_t w[44],const uint8_t k[16]){
    int i;for(i=0;i<4;i++)w[i]=(k[i*4]<<24)|(k[i*4+1]<<16)|(k[i*4+2]<<8)|k[i*4+3];
    for(i=4;i<44;i++){
        uint32_t t=w[i-1];
        if(i%4==0)t=aes_subw(aes_rotw(t))^aes_rcon[i/4-1];
        w[i]=w[i-4]^t;
    }
}
#define AES_XTIME(x) (((x<<1)^(((x>>7)&1)*0x1b))&0xff)
static void aes_encrypt_block(uint8_t out[16],const uint8_t in[16],const uint32_t w[44]){
    uint8_t s[16];int i,r;memcpy(s,in,16);
    for(i=0;i<4;i++){
        s[i*4]^=(w[i]>>24)&0xff;s[i*4+1]^=(w[i]>>16)&0xff;
        s[i*4+2]^=(w[i]>>8)&0xff;s[i*4+3]^=w[i]&0xff;
    }
    for(r=1;r<=10;r++){
        for(i=0;i<16;i++)s[i]=aes_sbox[s[i]];
        {uint8_t t;t=s[1];s[1]=s[5];s[5]=s[9];s[9]=s[13];s[13]=t;
         t=s[2];s[2]=s[10];s[10]=t;t=s[6];s[6]=s[14];s[14]=t;
         t=s[15];s[15]=s[11];s[11]=s[7];s[7]=s[3];s[3]=t;}
        if(r<10)for(i=0;i<4;i++){
            uint8_t a=s[i*4],b=s[i*4+1],c=s[i*4+2],d=s[i*4+3];
            s[i*4]=AES_XTIME(a)^AES_XTIME(b)^b^c^d;
            s[i*4+1]=a^AES_XTIME(b)^AES_XTIME(c)^c^d;
            s[i*4+2]=a^b^AES_XTIME(c)^AES_XTIME(d)^d;
            s[i*4+3]=AES_XTIME(a)^a^b^c^AES_XTIME(d);
        }
        for(i=0;i<4;i++){
            uint32_t kw=w[r*4+i];
            s[i*4]^=(kw>>24)&0xff;s[i*4+1]^=(kw>>16)&0xff;
            s[i*4+2]^=(kw>>8)&0xff;s[i*4+3]^=kw&0xff;
        }
    }
    memcpy(out,s,16);
}
typedef struct { uint64_t HH[16], HL[16]; uint8_t h[16]; } gcm_table;
static const uint16_t gcm_last4[16] = {
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0
};
static uint64_t gcm_be64(const uint8_t *p) {
    uint64_t r = 0; for (int i = 0; i < 8; i++) r = (r << 8) | p[i]; return r;
}
static void gcm_table_init(gcm_table *t, const uint8_t h[16]) {
    memcpy(t->h, h, 16);
    uint64_t hi = gcm_be64(h), lo = gcm_be64(h + 8);
    t->HH[0] = 0; t->HL[0] = 0;
    t->HH[8] = hi; t->HL[8] = lo;
    for (int i = 4; i > 0; i >>= 1) {
        uint32_t T = (uint32_t)(lo & 1) * 0xe1000000u;
        lo = (hi << 63) | (lo >> 1);
        hi = (hi >> 1) ^ ((uint64_t)T << 32);
        t->HL[i] = lo; t->HH[i] = hi;
    }
    for (int i = 2; i <= 8; i *= 2)
        for (int j = 1; j < i; j++) {
            t->HH[i + j] = t->HH[i] ^ t->HH[j];
            t->HL[i + j] = t->HL[i] ^ t->HL[j];
        }
}
static void gcm_mul_tab(const gcm_table *t, uint8_t x[16]) {
    uint8_t lo = x[15] & 0x0f;
    uint64_t zh = t->HH[lo], zl = t->HL[lo];
    for (int i = 15; i >= 0; i--) {
        lo = x[i] & 0x0f;
        uint8_t hi = (x[i] >> 4) & 0x0f;
        uint8_t rem;
        if (i != 15) {
            rem = (uint8_t)(zl & 0x0f);
            zl = (zh << 60) | (zl >> 4);
            zh = (zh >> 4) ^ ((uint64_t)gcm_last4[rem] << 48);
            zh ^= t->HH[lo]; zl ^= t->HL[lo];
        }
        rem = (uint8_t)(zl & 0x0f);
        zl = (zh << 60) | (zl >> 4);
        zh = (zh >> 4) ^ ((uint64_t)gcm_last4[rem] << 48);
        zh ^= t->HH[hi]; zl ^= t->HL[hi];
    }
    for (int i = 0; i < 8; i++) { x[i] = (uint8_t)(zh >> (56 - 8*i)); x[8+i] = (uint8_t)(zl >> (56 - 8*i)); }
}
static void gcm_ghash(uint8_t *y, const gcm_table *t, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        size_t n = (len - i < 16) ? (len - i) : 16;
        for (size_t j = 0; j < n; j++) y[j] ^= data[i + j];
        gcm_mul_tab(t, y);
    }
}
static void aes_gcm_encrypt(uint8_t *ct, uint8_t tag[16],
                            const uint8_t *pt, size_t len,
                            const uint8_t key[16],
                            const uint8_t iv[12],
                            const uint8_t *aad, size_t alen)
{
    uint32_t w[44];
    aes_key_expand(w, key);   
    uint8_t h[16] = {0};
    aes_encrypt_block(h, (const uint8_t[16]){0}, w);
    gcm_table tbl;
    gcm_table_init(&tbl, h);
    uint8_t j0[16] = {0};
    memcpy(j0, iv, 12);
    j0[15] = 1;
    uint8_t ctr[16];
    memcpy(ctr, j0, 16);
    for (int i = 15; i >= 12; i--)
        if (++ctr[i]) break;   
    for (size_t off = 0; off < len; off += 16) {
        uint8_t mask[16];
        aes_encrypt_block(mask, ctr, w);
        size_t n = len - off;
        if (n > 16) n = 16;
        for (size_t i = 0; i < n; i++) ct[off + i] = pt[off + i] ^ mask[i];
        for (int i = 15; i >= 12; i--) if (++ctr[i]) break;
    }
    uint8_t y[16] = {0};
    if (aad && alen) gcm_ghash(y, &tbl, aad, alen);
    gcm_ghash(y, &tbl, ct, len);
    uint8_t lb[16] = {0};
    uint64_t al64 = (uint64_t)alen * 8;
    uint64_t cl64 = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) {
        lb[7-i] = al64 >> (i * 8);
        lb[15-i] = cl64 >> (i * 8);
    }
    gcm_ghash(y, &tbl, lb, 16);
    uint8_t tagmask[16];
    aes_encrypt_block(tagmask, j0, w);
    for (int i = 0; i < 16; i++) tag[i] = y[i] ^ tagmask[i];
}
static int aes_gcm_decrypt(uint8_t *pt,
                           const uint8_t *ct, size_t len,
                           const uint8_t key[16],
                           const uint8_t iv[12],
                           const uint8_t tag[16],
                           const uint8_t *aad, size_t alen)
{
    uint32_t w[44];
    aes_key_expand(w, key);
    uint8_t h[16] = {0};
    aes_encrypt_block(h, (const uint8_t[16]){0}, w);
    gcm_table tbl;
    gcm_table_init(&tbl, h);
    uint8_t j0[16] = {0};
    memcpy(j0, iv, 12);
    j0[15] = 1;
    uint8_t y[16] = {0};
    if (aad && alen) gcm_ghash(y, &tbl, aad, alen);
    gcm_ghash(y, &tbl, ct, len);
    uint8_t lb[16] = {0};
    uint64_t al64 = (uint64_t)alen * 8;
    uint64_t cl64 = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) {
        lb[7-i] = al64 >> (i * 8);
        lb[15-i] = cl64 >> (i * 8);
    }
    gcm_ghash(y, &tbl, lb, 16);
    uint8_t tagmask[16];
    aes_encrypt_block(tagmask, j0, w);
    for (int i = 0; i < 16; i++)
        if ((y[i] ^ tagmask[i]) != tag[i])
            return -1;
    uint8_t ctr[16];
    memcpy(ctr, j0, 16);
    for (int i = 15; i >= 12; i--)
        if (++ctr[i]) break;
    for (size_t off = 0; off < len; off += 16) {
        uint8_t mask[16];
        aes_encrypt_block(mask, ctr, w);
        size_t n = len - off;
        if (n > 16) n = 16;
        for (size_t i = 0; i < n; i++) pt[off + i] = ct[off + i] ^ mask[i];
        for (int i = 15; i >= 12; i--) if (++ctr[i]) break;
    }
    return (int)len;
}
static uint32_t chacha_rotl(uint32_t x,int n){return(x<<n)|(x>>(32-n));}
static void chacha20_block(uint8_t out[64],const uint32_t key[8],uint32_t ctr,const uint32_t nonce[3]){
    uint32_t x[16];int i;
    x[0]=0x61707865;x[1]=0x3320646e;x[2]=0x79622d32;x[3]=0x6b206574;
    for(i=0;i<8;i++)x[4+i]=key[i];x[12]=ctr;for(i=0;i<3;i++)x[13+i]=nonce[i];
    uint32_t v[16];memcpy(v,x,64);
    for(i=0;i<10;i++){
        v[0]+=v[4];v[12]=chacha_rotl(v[12]^v[0],16);v[8]+=v[12];v[4]=chacha_rotl(v[4]^v[8],12);
        v[0]+=v[4];v[12]=chacha_rotl(v[12]^v[0],8);v[8]+=v[12];v[4]=chacha_rotl(v[4]^v[8],7);
        v[1]+=v[5];v[13]=chacha_rotl(v[13]^v[1],16);v[9]+=v[13];v[5]=chacha_rotl(v[5]^v[9],12);
        v[1]+=v[5];v[13]=chacha_rotl(v[13]^v[1],8);v[9]+=v[13];v[5]=chacha_rotl(v[5]^v[9],7);
        v[2]+=v[6];v[14]=chacha_rotl(v[14]^v[2],16);v[10]+=v[14];v[6]=chacha_rotl(v[6]^v[10],12);
        v[2]+=v[6];v[14]=chacha_rotl(v[14]^v[2],8);v[10]+=v[14];v[6]=chacha_rotl(v[6]^v[10],7);
        v[3]+=v[7];v[15]=chacha_rotl(v[15]^v[3],16);v[11]+=v[15];v[7]=chacha_rotl(v[7]^v[11],12);
        v[3]+=v[7];v[15]=chacha_rotl(v[15]^v[3],8);v[11]+=v[15];v[7]=chacha_rotl(v[7]^v[11],7);
        v[0]+=v[5];v[15]=chacha_rotl(v[15]^v[0],16);v[10]+=v[15];v[5]=chacha_rotl(v[5]^v[10],12);
        v[0]+=v[5];v[15]=chacha_rotl(v[15]^v[0],8);v[10]+=v[15];v[5]=chacha_rotl(v[5]^v[10],7);
        v[1]+=v[6];v[12]=chacha_rotl(v[12]^v[1],16);v[11]+=v[12];v[6]=chacha_rotl(v[6]^v[11],12);
        v[1]+=v[6];v[12]=chacha_rotl(v[12]^v[1],8);v[11]+=v[12];v[6]=chacha_rotl(v[6]^v[11],7);
        v[2]+=v[7];v[13]=chacha_rotl(v[13]^v[2],16);v[8]+=v[13];v[7]=chacha_rotl(v[7]^v[8],12);
        v[2]+=v[7];v[13]=chacha_rotl(v[13]^v[2],8);v[8]+=v[13];v[7]=chacha_rotl(v[7]^v[8],7);
        v[3]+=v[4];v[14]=chacha_rotl(v[14]^v[3],16);v[9]+=v[14];v[4]=chacha_rotl(v[4]^v[9],12);
        v[3]+=v[4];v[14]=chacha_rotl(v[14]^v[3],8);v[9]+=v[14];v[4]=chacha_rotl(v[4]^v[9],7);
    }
    for(i=0;i<16;i++){uint32_t s=x[i]+v[i];out[i*4]=s;out[i*4+1]=s>>8;out[i*4+2]=s>>16;out[i*4+3]=s>>24;}
}
static void poly1305_mac(uint8_t out[16],const uint8_t*msg,size_t len,const uint8_t key[32]){
    uint32_t r[4],h[5]={0};int i;for(i=0;i<4;i++)
        r[i]=((uint32_t)key[i*4]|((uint32_t)key[i*4+1]<<8)|((uint32_t)key[i*4+2]<<16)|((uint32_t)key[i*4+3]<<24))&0x3ffffff;
    r[3]&=0x3ffffff;
    size_t off=0;
    while(len>=16){
        uint32_t d[5];for(i=0;i<4;i++)d[i]=((uint32_t)msg[off+i*4]|((uint32_t)msg[off+i*4+1]<<8)|((uint32_t)msg[off+i*4+2]<<16)|((uint32_t)msg[off+i*4+3]<<24))&0x3ffffff;
        d[4]=0x01000000;for(i=0;i<5;i++)h[i]+=d[i];
        uint64_t c[5]={0};for(i=0;i<5;i++){int j;for(j=0;j<=i&&j<4;j++)c[i]+=(uint64_t)h[j]*r[i-j];}
        for(i=0;i<4;i++){uint32_t carry=c[i]>>26;h[i]=c[i]&0x3ffffff;c[i+1]+=carry;}
        h[4]=c[4]&0x3ffffff;h[0]+=(c[4]>>26)*5;off+=16;len-=16;
    }
    if(len>0){uint8_t pad[16]={0};memcpy(pad,msg+off,len);pad[len]=1;
        uint32_t d[4];for(i=0;i<4;i++)d[i]=((uint32_t)pad[i*4]|((uint32_t)pad[i*4+1]<<8)|((uint32_t)pad[i*4+2]<<16)|((uint32_t)pad[i*4+3]<<24))&0x3ffffff;
        for(i=0;i<4;i++)h[i]+=d[i];}
    uint32_t g[5];for(i=0;i<5;i++)g[i]=h[i]+5;uint32_t mask=(g[4]>>31)-1;
    for(i=0;i<5;i++)h[i]=(h[i]&~mask)|(g[i]&mask);
    uint32_t f[4];f[0]=h[0]|(h[1]<<26);f[1]=(h[1]>>6)|(h[2]<<20);f[2]=(h[2]>>12)|(h[3]<<14);f[3]=(h[3]>>18)|(h[4]<<8);
    uint64_t acc=f[0]+((uint64_t)key[16]|((uint64_t)key[17]<<8)|((uint64_t)key[18]<<16)|((uint64_t)key[19]<<24));
    for(i=1;i<4;i++){
        acc+=f[i]+((uint64_t)key[16+i*4]|((uint64_t)key[16+i*4+1]<<8)|((uint64_t)key[16+i*4+2]<<16)|((uint64_t)key[16+i*4+3]<<24));
        out[i*4-1]=acc&0xff;acc>>=8;out[i*4]=acc&0xff;acc>>=8;out[i*4+1]=acc&0xff;acc>>=8;out[i*4+2]=acc&0xff;acc>>=8;
    }
}
static void chacha_poly_encrypt(uint8_t*ct,uint8_t tag[16],const uint8_t*pt,size_t len,
                                 const uint8_t key[32],const uint8_t nonce[12],
                                 const uint8_t*aad,size_t alen){
    uint32_t kw[8],nw[3];uint8_t poly_key[64]={0},block[64];int i;
    for(i=0;i<8;i++)kw[i]=((uint32_t)key[i*4]|((uint32_t)key[i*4+1]<<8)|((uint32_t)key[i*4+2]<<16)|((uint32_t)key[i*4+3]<<24));
    for(i=0;i<3;i++)nw[i]=((uint32_t)nonce[i*4]|((uint32_t)nonce[i*4+1]<<8)|((uint32_t)nonce[i*4+2]<<16)|((uint32_t)nonce[i*4+3]<<24));
    chacha20_block(poly_key,kw,0,nw);size_t off=0;uint32_t ctr=1;
    while(off<len){chacha20_block(block,kw,ctr++,nw);size_t j;for(j=0;j<64&&(off+j)<len;j++)ct[off+j]=pt[off+j]^block[j];off+=j;}
    uint8_t mac_in[64]; size_t ml = 0;
    if (aad && alen) {
        size_t pad = (16 - alen % 16) % 16;
        memcpy(mac_in, aad, alen); memset(mac_in + alen, 0, pad);
        ml = alen + pad;
    }
    size_t cpad = (16 - len % 16) % 16;
    memcpy(mac_in + ml, ct, len); ml += len;
    memset(mac_in + ml, 0, cpad); ml += cpad;
    uint64_t le_alen = alen, le_len = len;
    for (i = 0; i < 8; i++) { mac_in[ml+i] = le_alen & 0xff; le_alen >>= 8; }
    ml += 8;
    for (i = 0; i < 8; i++) { mac_in[ml+i] = le_len & 0xff; le_len >>= 8; }
    ml += 8;
    poly1305_mac(tag, mac_in, ml, poly_key);
}
static int chacha_poly_decrypt(uint8_t*pt,const uint8_t*ct,size_t len,
                                const uint8_t key[32],const uint8_t nonce[12],
                                const uint8_t tag[16],
                                const uint8_t*aad,size_t alen){
    uint8_t calc[16];chacha_poly_encrypt(pt,calc,ct,len,key,nonce,aad,alen);
    int i;for(i=0;i<16;i++)if(calc[i]!=tag[i])return-1;return(int)len;
}
static int full_write(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf;
    while (n) { ssize_t w = send(fd, p, n, MSG_NOSIGNAL); if (w <= 0) return -1; p += w; n -= w; }
    return 0;
}
static int recv_all(int fd, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) { ssize_t r = recv(fd, buf + off, n - off, 0); if (r <= 0) return -1; off += r; }
    return 0;
}
struct planck_conn {
    int fd;
    int tls_version;  
    int http_version; 
    int cipher;       
    uint8_t ck[32], sk[32], civ[12], siv[12];
    uint64_t cs, ss;
    uint8_t tx[MAX_BUF], rx[MAX_BUF];
    uint8_t hs_sk[32], hs_siv[12];
    uint64_t hs_ss;
};
static int tls_encrypt(planck_conn *c, const uint8_t *pt, int ptlen, uint8_t *out, uint8_t record_type, uint8_t vh, uint8_t vl);
static int tls_decrypt_app(planck_conn *c, const uint8_t *ct, int ctlen, uint8_t *pt, uint8_t record_type, uint8_t vh, uint8_t vl);
static int tls_decrypt(planck_conn *c, const uint8_t *ct, int ctlen, uint8_t *pt, uint8_t record_type, uint8_t vh, uint8_t vl);
static int tls_decrypt_any(planck_conn *c, const uint8_t *ct, int ctlen, uint8_t *pt, uint8_t vh, uint8_t vl, int *used_handshake_keys);
static int tls13_handshake(planck_conn *c, const char *sni, int http_version) {
    uint8_t ch[2048], *p = ch, client_random[32], priv[32], pub[32];
    int i;
    for (i = 0; i < 32; i++) client_random[i] = rand() & 0xff;
    for (i = 0; i < 32; i++) priv[i] = rand() & 0xff;
    x25519_keygen(pub, priv);
    { int _i; LOG( "[TLS13] priv="); for(_i=0;_i<32;_i++)LOG("%02x",priv[_i]);LOG("\n"); }
    { int _i; LOG( "[TLS13] pub="); for(_i=0;_i<32;_i++)LOG("%02x",pub[_i]);LOG("\n"); }
    LOG( "[TLS13] Building ClientHello\n");
    *p++ = TLS_CONTENT_HANDSHAKE; *p++ = 0x03; *p++ = 0x01;
    uint16_t *rl = (uint16_t*)p; p += 2;
    *p++ = TLS_HS_CLIENT_HELLO; uint8_t *hl = p; p += 3;
    *p++ = 0x03; *p++ = 0x03;
    memcpy(p, client_random, 32); p += 32; *p++ = 0;
    *p++ = 0x00; *p++ = 0x04; *p++ = 0x13; *p++ = 0x01; *p++ = 0x13; *p++ = 0x03;
    *p++ = 1; *p++ = 0;
    uint16_t *el = (uint16_t*)p; p += 2;
    *p++ = 0x00; *p++ = 0x00; uint16_t *sl = (uint16_t*)p; p += 2;
    size_t sn = strlen(sni);
    uint16_t ll = 3 + sn;
    *p++ = (ll >> 8) & 0xff; *p++ = ll & 0xff;
    *p++ = 0x00; *p++ = (sn >> 8) & 0xff; *p++ = sn & 0xff;
    memcpy(p, sni, sn); p += sn;
    *sl = htons(p - (uint8_t*)sl - 2);
    *p++ = 0x00; *p++ = 0x0a; *p++ = 0x00; *p++ = 0x04; *p++ = 0x00; *p++ = 0x02; *p++ = 0x00; *p++ = 0x1d;
    *p++ = 0x00; *p++ = 0x33; uint16_t *kl = (uint16_t*)p; p += 2;
    *p++ = 0x00; *p++ = 0x24;
    *p++ = 0x00; *p++ = 0x1d; *p++ = 0x00; *p++ = 0x20; memcpy(p, pub, 32); p += 32;
    *kl = htons(p - (uint8_t*)kl - 2);
    *p++ = 0x00; *p++ = 0x2b; *p++ = 0x00; *p++ = 0x03; *p++ = 0x02; *p++ = 0x03; *p++ = 0x04;
    *p++ = 0x00; *p++ = 0x2d; *p++ = 0x00; *p++ = 0x02; *p++ = 0x01; *p++ = 0x01;
    *p++ = 0x00; *p++ = 0x0d; *p++ = 0x00; *p++ = 0x08; *p++ = 0x00; *p++ = 0x06;
    *p++ = 0x04; *p++ = 0x03; *p++ = 0x08; *p++ = 0x04; *p++ = 0x08; *p++ = 0x05;
    *p++ = 0x00; *p++ = 0x10; uint16_t *al = (uint16_t*)p; p += 2;
    uint8_t *pl = p; p += 2;
    if (http_version == 2) {
        *p++ = 0x02; *p++ = 'h'; *p++ = '2';
    } else {
        *p++ = 0x08; *p++ = 'h'; *p++ = 't'; *p++ = 't'; *p++ = 'p'; *p++ = '/'; *p++ = '1'; *p++ = '.'; *p++ = '1';
    }
    *(uint16_t*)pl = htons(p - pl - 2);
    *al = htons(p - (uint8_t*)al - 2);
    *el = htons(p - (uint8_t*)el - 2);
    uint32_t hlen = p - (uint8_t*)hl - 3;
    hl[0] = (hlen >> 16) & 0xff; hl[1] = (hlen >> 8) & 0xff; hl[2] = hlen & 0xff;
    *rl = htons(p - ch - 5);
    sha256_ctx transcript;
    sha256_init(&transcript);
    sha256_update(&transcript, ch + 5, p - ch - 5);
    LOG( "[TLS13] Sending ClientHello (%d bytes)\n", (int)(p - ch));
    if (full_write(c->fd, ch, p - ch)) { LOG( "[TLS13] SEND FAILED\n"); return -1; }
    uint8_t buf[8192];
    int n; uint16_t rlen;
    for (;;) {
        n = recv(c->fd, buf, 5, 0);
        if (n != 5) { LOG( "[TLS13] recv record header failed (got %d)\n", n); return -1; }
        uint8_t ct = buf[0];
        rlen = (buf[3] << 8) | buf[4];
        if (rlen > sizeof(buf) - 5) { LOG( "[TLS13] record too large\n"); return -1; }
        if (recv_all(c->fd, buf + 5, rlen)) { LOG( "[TLS13] recv body failed\n"); return -1; }
        if (ct == 20) { LOG( "[TLS13] skipping CCS\n"); continue; }
        if (ct == 21) {
            if (rlen >= 2) LOG( "[TLS13] Alert level=%d desc=%d\n", buf[5], buf[6]);
            return -1;
        }
        if (ct == TLS_CONTENT_HANDSHAKE) {
            sha256_update(&transcript, buf + 5, rlen);
            LOG( "[TLS13] ServerHello record length = %u\n", rlen);
            break;
        }
        LOG( "[TLS13] unexpected content type %02x\n", ct); return -1;
    }
    uint8_t *ptr = buf + 5;
    if (*ptr != TLS_HS_SERVER_HELLO) { LOG( "[TLS13] expected ServerHello, got %02x\n", *ptr); return -1; }
    ptr += 4; ptr += 2;
    uint8_t server_random[32]; memcpy(server_random, ptr, 32); ptr += 32;
    uint8_t sid_len = *ptr; ptr += 1 + sid_len;
    uint16_t cs = (ptr[0] << 8) | ptr[1]; ptr += 2;
    if (cs == 0x1303) c->cipher = 1;
    else if (cs == 0x1301) c->cipher = 0;
    else { LOG("[TLS13] unsupported cipher suite 0x%04x\n", cs); return -1; }
    LOG( "[TLS13] cipher suite = 0x%04x (%s)\n", cs, c->cipher ? "ChaCha" : "AES");
    int klen = c->cipher ? 32 : 16;
    ptr++;
    uint16_t ext_len = (ptr[0] << 8) | ptr[1]; ptr += 2;
    uint8_t *ext_end = ptr + ext_len;
    uint8_t peer_pub[32]; int found = 0;
    while (ptr < ext_end) {
        uint16_t type = (ptr[0] << 8) | ptr[1], elen = (ptr[2] << 8) | ptr[3]; ptr += 4;
        if (type == 0x0033) {
            ptr += 4; memcpy(peer_pub, ptr, 32); found = 1;
            LOG( "[TLS13] found key_share\n"); break;
        }
        ptr += elen;
    }
    if (!found) { LOG( "[TLS13] no key_share in ServerHello\n"); return -1; }
    uint8_t ss[32]; x25519_scalar_mult(ss, priv, peer_pub);
    LOG( "[TLS13] shared secret computed\n");
    uint8_t early[32], hs[32], derived[32], th[32], th_hello[32], z[32] = {0};
    uint8_t empty_hash[32] = {0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55};
    hkdf_extract(early, NULL, 0, z, 32);
    hkdf_expand_label(derived, 32, early, "derived", empty_hash, 32);
    uint8_t pre[32]; hkdf_extract(pre, derived, 32, ss, 32);
    sha256_ctx th_ctx;
    sha256_init(&th_ctx);
    sha256_update(&th_ctx, ch + 5, p - ch - 5);
    sha256_update(&th_ctx, buf + 5, rlen);
    sha256_final(th, &th_ctx);  
    memcpy(th_hello, th, 32);   
    hkdf_expand_label(hs, 32, pre, "s hs traffic", th, 32);
    hkdf_expand_label(c->hs_sk, klen, hs, "key", NULL, 0);
    hkdf_expand_label(c->hs_siv, 12,  hs, "iv",  NULL, 0);
    c->hs_ss = 0;
    for (;;) {
        n = recv(c->fd, buf, 5, 0);
        if (n != 5) return -1;
        rlen = (buf[3] << 8) | buf[4];
        if (buf[0] == 20) { if (recv_all(c->fd, buf + 5, rlen)) return -1; continue; }
        if (buf[0] != TLS_CONTENT_APP_DATA) return -1;
        break;
    }
    if (recv_all(c->fd, buf + 5, rlen)) return -1;
    uint8_t plain[MAX_BUF];
    uint8_t hs_key[32], hs_iv[12];
    hkdf_expand_label(hs_key, klen, hs, "key", NULL, 0);
    hkdf_expand_label(hs_iv, 12, hs, "iv", NULL, 0);
    uint8_t nonce[12]; memcpy(nonce, hs_iv, 12);
    int ptlen = rlen - AES_GCM_TAG_SIZE;
    int dec;
    { uint8_t aad[5] = {0x17, buf[1], buf[2], (uint8_t)(rlen >> 8), (uint8_t)(rlen & 0xff)};
    if (c->cipher) dec = chacha_poly_decrypt(plain, buf + 5, ptlen, hs_key, nonce, buf + 5 + ptlen, aad, 5);
    else           dec = aes_gcm_decrypt(plain, buf + 5, ptlen, hs_key, nonce, buf + 5 + ptlen, aad, 5);
    if (dec < 0) return -1; }
    if (ptlen < 1) return -1;
    uint8_t inner_ct = plain[ptlen - 1]; ptlen--;
    if (inner_ct != TLS_CONTENT_HANDSHAKE) return -1;
    uint8_t *pf = plain, *pend = plain + ptlen;
    uint8_t sfin[32];
    int got_fin = 0, h2_ok = 0;
    uint8_t *finished_start = NULL;
    uint32_t finished_len = 0;
    while (pf < pend) {
        uint8_t mt = *pf++;
        uint32_t ml = (pf[0] << 16) | (pf[1] << 8) | pf[2];
        pf += 3;
        if (pf + ml > pend) return -1;
        uint8_t *msg_start = pf - 4;
        size_t   msg_total = 4 + ml;
        if (mt == TLS_HS_FINISHED) {
            if (ml != 32) return -1;
            memcpy(sfin, pf, 32); got_fin = 1;
            finished_start = msg_start; finished_len = msg_total; break;
        }
        sha256_update(&transcript, msg_start, msg_total);
        if (mt == TLS_HS_ENCRYPTED_EXTENSIONS) {
            uint8_t *ex = pf, *ex_end = pf + ml;
            if (ex_end - ex >= 2) {
                uint16_t ext_list_len = (ex[0] << 8) | ex[1]; ex += 2;
                uint8_t *ext_list_end = ex + ext_list_len;
                while (ex + 4 <= ext_list_end) {
                    uint16_t ext_type = (ex[0] << 8) | ex[1];
                    uint16_t ext_data_len = (ex[2] << 8) | ex[3]; ex += 4;
                    if (ex + ext_data_len > ext_list_end) break;
                    if (ext_type == 16) {
                        uint8_t *al = ex + 2, *al_end = ex + ext_data_len;
                        while (al < al_end) {
                            uint8_t pnl = *al++;
                            if (pnl == 2 && al + 2 <= al_end && al[0] == 'h' && al[1] == '2') h2_ok = 1;
                            al += pnl;
                        }
                    }
                    ex += ext_data_len;
                }
            }
        }
        pf += ml;
    }
    if (!got_fin) return -1;
    sha256_ctx verify_ctx;
    memcpy(&verify_ctx, &transcript, sizeof(verify_ctx));
    sha256_final(th, &verify_ctx);
    uint8_t finished_key[32];
    hkdf_expand_label(finished_key, 32, hs, "finished", NULL, 0);
    uint8_t expected[32];
    hmac_sha256(expected, finished_key, 32, th, 32);
    if (memcmp(sfin, expected, 32)) return -1;
    sha256_update(&transcript, finished_start, finished_len);
    sha256_ctx pre_cf_ctx;
    memcpy(&pre_cf_ctx, &transcript, sizeof(pre_cf_ctx));
    uint8_t hash_before_client_finished[32];
    sha256_final(hash_before_client_finished, &pre_cf_ctx);
    uint8_t zero[32] = {0};
    uint8_t hs_derived[32];
    hkdf_expand_label(hs_derived, 32, pre, "derived", empty_hash, 32);
    uint8_t master_secret[32];
    hkdf_extract(master_secret, hs_derived, 32, zero, 32);
    uint8_t client_hs_secret[32];
    hkdf_expand_label(client_hs_secret, 32, pre, "c hs traffic", th_hello, 32);
    uint8_t chs_key[32], chs_iv[12];
    hkdf_expand_label(chs_key, klen, client_hs_secret, "key", NULL, 0);
    hkdf_expand_label(chs_iv, 12, client_hs_secret, "iv", NULL, 0);
    uint8_t cf_payload[64], *cp = cf_payload;
    *cp++ = TLS_HS_FINISHED; *cp++ = 0x00; *cp++ = 0x00; *cp++ = 0x20;
    uint8_t client_finished_key[32];
    hkdf_expand_label(client_finished_key, 32, client_hs_secret, "finished", NULL, 0);
    uint8_t cverify[32];
    hmac_sha256(cverify, client_finished_key, 32, hash_before_client_finished, 32);
    memcpy(cp, cverify, 32); cp += 32;
    sha256_update(&transcript, cf_payload, cp - cf_payload);
    sha256_final(th, &transcript); 
    *cp++ = TLS_CONTENT_HANDSHAKE;   
    int cf_ptlen = cp - cf_payload;
    uint8_t cf_nonce[12]; memcpy(cf_nonce, chs_iv, 12);
    uint8_t cf_tag[16], cf_enc[256];
    uint8_t caad[5] = {0x17, 0x03, 0x03, (uint8_t)((cf_ptlen + 16) >> 8), (uint8_t)((cf_ptlen + 16) & 0xff)};
    if (c->cipher) chacha_poly_encrypt(cf_enc, cf_tag, cf_payload, cf_ptlen, chs_key, cf_nonce, caad, 5);
    else           aes_gcm_encrypt(cf_enc, cf_tag, cf_payload, cf_ptlen, chs_key, cf_nonce, caad, 5);
    uint8_t cf_rec[5] = { TLS_CONTENT_APP_DATA, 0x03, 0x03 };
    uint16_t cf_rl = htons(cf_ptlen + 16); memcpy(cf_rec + 3, &cf_rl, 2);
    if (full_write(c->fd, cf_rec, 5) || full_write(c->fd, cf_enc, cf_ptlen) || full_write(c->fd, cf_tag, 16)) return -1;
    uint8_t server_traffic_secret[32];
    hkdf_expand_label(server_traffic_secret, 32, master_secret, "s ap traffic", hash_before_client_finished, 32);
    hkdf_expand_label(c->sk, klen, server_traffic_secret, "key", NULL, 0);
    hkdf_expand_label(c->siv, 12,  server_traffic_secret, "iv",  NULL, 0);
    c->ss = 0;
    uint8_t client_traffic_secret[32];
    hkdf_expand_label(client_traffic_secret, 32, master_secret, "c ap traffic", hash_before_client_finished, 32);
    hkdf_expand_label(c->ck, klen, client_traffic_secret, "key", NULL, 0);
    hkdf_expand_label(c->civ, 12,   client_traffic_secret, "iv",  NULL, 0);
    c->cs = 0;
    c->tls_version = 13;
    c->http_version = http_version;
    LOG( "[TLS13] handshake complete\n");
    return 0;
}
static int tls12_handshake(planck_conn *c, const char *sni, int http_version) {
    uint8_t ch[2048], *p = ch, client_random[32], priv[32], pub[32]; int i;
    for (i = 0; i < 32; i++) { client_random[i] = rand() & 0xff; priv[i] = rand() & 0xff; }
    x25519_keygen(pub, priv);
    sha256_ctx th; sha256_init(&th);
    *p++ = TLS_CONTENT_HANDSHAKE; *p++ = 0x03; *p++ = 0x01;
    uint16_t *rl = (uint16_t*)p; p += 2;
    *p++ = TLS_HS_CLIENT_HELLO; uint8_t *hl = p; p += 3;
    *p++ = 0x03; *p++ = 0x03; memcpy(p, client_random, 32); p += 32; *p++ = 0;
    *p++ = 0x00; *p++ = 0x04; *p++ = 0xc0; *p++ = 0x2b; *p++ = 0xcc; *p++ = 0xa9;
    *p++ = 1; *p++ = 0;
    uint16_t *el = (uint16_t*)p; p += 2;
    *p++ = 0x00; *p++ = 0x00; uint16_t *sl = (uint16_t*)p; p += 2;
    size_t sn = strlen(sni);
    uint16_t ll = 3 + sn;
    *p++ = (ll >> 8) & 0xff; *p++ = ll & 0xff;
    *p++ = 0x00; *p++ = (sn >> 8) & 0xff; *p++ = sn & 0xff;
    memcpy(p, sni, sn); p += sn;
    *sl = htons(p - (uint8_t*)sl - 2);
    *p++ = 0x00; *p++ = 0x0a; *p++ = 0x00; *p++ = 0x04; *p++ = 0x00; *p++ = 0x02; *p++ = 0x00; *p++ = 0x1d;
    *p++ = 0x00; *p++ = 0x0d; *p++ = 0x00; *p++ = 0x08; *p++ = 0x00; *p++ = 0x06;
    *p++ = 0x04; *p++ = 0x03; *p++ = 0x08; *p++ = 0x04; *p++ = 0x08; *p++ = 0x05;
    *p++ = 0x00; *p++ = 0x10; uint16_t *al = (uint16_t*)p; p += 2;
    { uint16_t pl_off = p - (uint8_t*)al - 2; uint8_t *pl = p; p += 2;
      if (http_version == 2) {
          *p++ = 0x02; *p++ = 'h'; *p++ = '2';
      } else {
          *p++ = 0x08; *p++ = 'h'; *p++ = 't'; *p++ = 't'; *p++ = 'p'; *p++ = '/'; *p++ = '1'; *p++ = '.'; *p++ = '1';
      }
      uint16_t pl_len = p - pl - 2; pl[0] = (pl_len >> 8) & 0xff; pl[1] = pl_len & 0xff;
      *al = htons(p - (uint8_t*)al - 2); }
    *el = htons(p - (uint8_t*)el - 2);
    uint32_t hl32 = p - (uint8_t*)hl - 3;
    hl[0] = (hl32 >> 16) & 0xff; hl[1] = (hl32 >> 8) & 0xff; hl[2] = hl32 & 0xff;
    *rl = htons(p - ch - 5);
    sha256_update(&th, ch + 5, p - ch - 5);
    if (full_write(c->fd, ch, p - ch)) return -1;
    uint8_t buf[8192], peer_pub[32], server_random[32]; 
    int got_pub = 0, got_server_hello = 0, got_server_hello_done = 0;
    while (!got_server_hello_done) {
        int n = recv(c->fd, buf, 5, 0);
        if (n != 5) return -1;
        uint16_t rlen = (buf[3] << 8) | buf[4];
        if (recv_all(c->fd, buf + 5, rlen)) return -1;
        sha256_update(&th, buf + 5, rlen);
        uint8_t *ptr = buf + 5, *end = ptr + rlen;
        while (ptr < end) {
            uint8_t mt = *ptr++; uint32_t ml = (ptr[0] << 16) | (ptr[1] << 8) | ptr[2]; ptr += 3;
            if (ptr + ml > end) return -1;
            if (mt == TLS_HS_SERVER_HELLO) {
                ptr += 2; memcpy(server_random, ptr, 32); ptr += 32;
                got_server_hello = 1;
                ptr += 1; ptr += ptr[-1];
                uint16_t cs = (ptr[0] << 8) | ptr[1]; c->cipher = (cs == 0xcca9) ? 1 : 0;
            }
            if (mt == TLS_HS_SERVER_KEY_EXCHANGE) {
                if (ml < 4 || ptr[0] != 3) return -1;
                if (ptr[1] != 0x00 || ptr[2] != 0x1d) return -1;
                if (ptr[3] != 0x20) return -1;
                memcpy(peer_pub, ptr + 4, 32); got_pub = 1;
            }
            if (mt == TLS_HS_SERVER_HELLO_DONE) {
                got_server_hello_done = 1;
            }
            ptr += ml;
        }
    }
    if (!got_server_hello || !got_pub) return -1;
    uint8_t ss[32]; x25519_scalar_mult(ss, priv, peer_pub);
    uint8_t seed[64]; memcpy(seed, client_random, 32); memcpy(seed + 32, server_random, 32);
    uint8_t master[48];
    tls12_prf_sha256(master, 48, ss, 32, "master secret", seed, 64);
    uint8_t key_exp_seed[64];
    memcpy(key_exp_seed, server_random, 32);
    memcpy(key_exp_seed + 32, client_random, 32);
    uint8_t key_block[128];
    tls12_prf_sha256(key_block, sizeof(key_block), master, 48, "key expansion", key_exp_seed, 64);
    if (c->cipher == 0) {
        memcpy(c->ck, key_block, 16); memcpy(c->sk, key_block + 16, 16);
        memcpy(c->civ, key_block + 32, 4); memset(c->civ + 4, 0, 8);
        memcpy(c->siv, key_block + 36, 4); memset(c->siv + 4, 0, 8);
    } else {
        memcpy(c->ck, key_block, 32); memcpy(c->sk, key_block + 32, 32);
        memcpy(c->civ, key_block + 64, 12); memcpy(c->siv, key_block + 76, 12);
    }
    uint8_t cke[70]; p = cke;
    *p++ = TLS_CONTENT_HANDSHAKE; *p++ = 0x03; *p++ = 0x03;
    uint16_t *ckrl = (uint16_t*)p; p += 2;
    *p++ = TLS_HS_CLIENT_KEY_EXCHANGE; uint8_t *ckhl = p; p += 3;
    *p++ = 32; 
    memcpy(p, pub, 32); p += 32;
    uint32_t ckhlen = p - ckhl - 3;
    ckhl[0] = (ckhlen >> 16) & 0xff; ckhl[1] = (ckhlen >> 8) & 0xff; ckhl[2] = ckhlen & 0xff;
    *ckrl = htons(p - (uint8_t*)ckrl - 2);
    sha256_update(&th, cke + 5, p - cke - 5);
    if (full_write(c->fd, cke, p - cke)) return -1;
    uint8_t ccs[6] = { TLS_CONTENT_CHANGE_CIPHER, 0x03, 0x03, 0x00, 0x01, 0x01 };
    if (full_write(c->fd, ccs, 6)) return -1;
    uint8_t thash[32]; sha256_final(thash, &th);
    uint8_t verify[12];
    tls12_prf_sha256(verify, 12, master, 48, "client finished", thash, 32);
    uint8_t fin_payload[16];
    fin_payload[0] = TLS_HS_FINISHED;
    fin_payload[1] = 0x00;
    fin_payload[2] = 0x00;
    fin_payload[3] = 12;
    memcpy(fin_payload + 4, verify, 12);
    uint8_t fin_enc[64];
    int fin_enc_len = tls_encrypt(c, fin_payload, 16, fin_enc, TLS_CONTENT_HANDSHAKE, 0x03, 0x03);
    uint8_t fin_rec[5] = { TLS_CONTENT_HANDSHAKE, 0x03, 0x03 };
    uint16_t fin_rl = htons(fin_enc_len);
    memcpy(fin_rec + 3, &fin_rl, 2);
    if (full_write(c->fd, fin_rec, 5) || full_write(c->fd, fin_enc, fin_enc_len)) return -1;
    if (recv_all(c->fd, buf, 6)) return -1;
    if (buf[0] != TLS_CONTENT_CHANGE_CIPHER) {
        LOG("[TLS12] Expected CCS, got %02x\n", buf[0]);
        return -1;
    }
    if (recv_all(c->fd, buf, 5)) return -1;
    uint16_t rlen = (buf[3] << 8) | buf[4];
    if (rlen > sizeof(buf) - 5) return -1;
    if (recv_all(c->fd, buf + 5, rlen)) return -1;
    uint8_t plain[256];
    int ptlen = tls_decrypt_app(c, buf + 5, rlen, plain, buf[0], buf[1], buf[2]);
    if (ptlen < 0) {
        LOG("[TLS12] Failed to decrypt server Finished\n");
        return -1;
    }
    LOG("[TLS12] Server Finished received and decrypted (%d bytes)\n", ptlen);
    c->tls_version = 12; 
    c->http_version = http_version;
    return 0;
}
static int tls_encrypt(planck_conn *c, const uint8_t *pt, int ptlen, uint8_t *out, uint8_t record_type, uint8_t vh, uint8_t vl) {
    if (c->tls_version == 13) {
        uint8_t nonce[12], tag[16]; memcpy(nonce, c->civ, 12);
        for (int i = 4; i < 12; i++) nonce[i] ^= (c->cs >> (8*(11-i))) & 0xff;
        c->cs++;
        int actual_ptlen = ptlen;
        uint8_t actual_pt[MAX_BUF + 1];
        memcpy(actual_pt, pt, ptlen);
        actual_pt[ptlen] = 0x17; 
        actual_ptlen = ptlen + 1;
        uint8_t aad[5] = {0x17, vh, vl, (uint8_t)((actual_ptlen+16) >> 8), (uint8_t)((actual_ptlen+16) & 0xff)};
        if (c->cipher) chacha_poly_encrypt(out, tag, actual_pt, actual_ptlen, c->ck, nonce, aad, 5);
        else           aes_gcm_encrypt(out, tag, actual_pt, actual_ptlen, c->ck, nonce, aad, 5);
        memcpy(out + actual_ptlen, tag, 16);
        return actual_ptlen + 16;
    } else {
        uint64_t seq = c->cs++;
        uint8_t aad[13]; 
        for(int i=0; i<8; i++) aad[i] = (seq >> (8*(7-i))) & 0xff;
        aad[8] = record_type; aad[9] = vh; aad[10] = vl;
        aad[11] = (ptlen >> 8) & 0xff; aad[12] = ptlen & 0xff;
        if (c->cipher == 1) {
            uint8_t nonce[12]; memcpy(nonce, c->civ, 12);
            for (int i = 4; i < 12; i++) nonce[i] ^= (seq >> (8*(11-i))) & 0xff;
            uint8_t tag[16];
            chacha_poly_encrypt(out, tag, pt, ptlen, c->ck, nonce, aad, 13);
            memcpy(out + ptlen, tag, 16);
            return ptlen + 16;
        } else {
            uint8_t explicit_nonce[8];
            for(int i=0; i<8; i++) explicit_nonce[i] = (seq >> (8*(7-i))) & 0xff;
            uint8_t nonce[12];
            memcpy(nonce, c->civ, 4); 
            memcpy(nonce + 4, explicit_nonce, 8); 
            uint8_t tag[16];
            memcpy(out, explicit_nonce, 8); 
            aes_gcm_encrypt(out + 8, tag, pt, ptlen, c->ck, nonce, aad, 13);
            memcpy(out + 8 + ptlen, tag, 16);
            return 8 + ptlen + 16;
        }
    }
}
static int tls_decrypt_app(planck_conn *c, const uint8_t *ct, int ctlen, uint8_t *pt, uint8_t record_type, uint8_t vh, uint8_t vl) {
    if (c->tls_version == 13) {
        uint8_t nonce[12]; memcpy(nonce, c->siv, 12);
        for (int i = 4; i < 12; i++) nonce[i] ^= (c->ss >> (8*(11-i))) & 0xff;
        int ptlen = ctlen - 16;
        uint8_t aad[5] = {0x17, vh, vl, (uint8_t)(ctlen >> 8), (uint8_t)(ctlen & 0xff)};
        int dec = c->cipher
            ? chacha_poly_decrypt(pt, ct, ptlen, c->sk, nonce, ct + ptlen, aad, 5)
            : aes_gcm_decrypt(pt, ct, ptlen, c->sk, nonce, ct + ptlen, aad, 5);
        if (dec >= 0) c->ss++;
        return dec;
    } else {
        uint64_t seq = c->ss;
        uint8_t aad[13];
        for(int i=0; i<8; i++) aad[i] = (seq >> (8*(7-i))) & 0xff;
        aad[8] = record_type; aad[9] = vh; aad[10] = vl;
        aad[11] = (ctlen >> 8) & 0xff; aad[12] = ctlen & 0xff; 
        int ptlen = 0;
        if (c->cipher == 1) {
            if (ctlen < 16) return -1;
            ptlen = ctlen - 16;
        } else {
            if (ctlen < 8 + 16) return -1;
            ptlen = ctlen - 8 - 16;
        }
        aad[11] = (ptlen >> 8) & 0xff; aad[12] = ptlen & 0xff;
        if (c->cipher == 1) {
            uint8_t nonce[12]; memcpy(nonce, c->siv, 12);
            for (int i = 4; i < 12; i++) nonce[i] ^= (seq >> (8*(11-i))) & 0xff;
            int dec = chacha_poly_decrypt(pt, ct, ptlen, c->sk, nonce, ct + ptlen, aad, 13);
            if (dec >= 0) c->ss++;
            return dec;
        } else {
            uint8_t explicit_nonce[8];
            memcpy(explicit_nonce, ct, 8); 
            uint8_t nonce[12];
            memcpy(nonce, c->siv, 4); 
            memcpy(nonce + 4, explicit_nonce, 8); 
            int dec = aes_gcm_decrypt(pt, ct + 8, ptlen, c->sk, nonce, ct + 8 + ptlen, aad, 13);
            if (dec >= 0) c->ss++;
            return dec;
        }
    }
}
static int tls_decrypt_hs(planck_conn *c, const uint8_t *ct, int ctlen, uint8_t *pt, uint8_t vh, uint8_t vl) {
    uint8_t nonce[12]; memcpy(nonce, c->hs_siv, 12);
    for (int i = 4; i < 12; i++) nonce[i] ^= (c->hs_ss >> (8*(11-i))) & 0xff;
    int ptlen = ctlen - 16;
    uint8_t aad[5] = {0x17, vh, vl, (uint8_t)(ctlen >> 8), (uint8_t)(ctlen & 0xff)};
    int dec = c->cipher
        ? chacha_poly_decrypt(pt, ct, ptlen, c->hs_sk, nonce, ct + ptlen, aad, 5)
        : aes_gcm_decrypt(pt, ct, ptlen, c->hs_sk, nonce, ct + ptlen, aad, 5);
    if (dec >= 0) c->hs_ss++;   
    return dec;
}
static int tls_decrypt_any(planck_conn *c, const uint8_t *ct, int ctlen, uint8_t *pt,
                           uint8_t vh, uint8_t vl, int *used_handshake_keys) {
    int dec = tls_decrypt_app(c, ct, ctlen, pt, 0x17, vh, vl);
    if (dec >= 0) {
        if (used_handshake_keys) *used_handshake_keys = 0;
        return dec;
    }
    dec = tls_decrypt_hs(c, ct, ctlen, pt, vh, vl);
    if (dec >= 0) {
        if (used_handshake_keys) *used_handshake_keys = 1;
        return dec;
    }
    return -1;
}
static int tls_decrypt(planck_conn *c, const uint8_t *ct, int ctlen, uint8_t *pt, uint8_t record_type, uint8_t vh, uint8_t vl) {
    return tls_decrypt_app(c, ct, ctlen, pt, record_type, vh, vl);
}
static uint8_t *h2_hpack_str(uint8_t *p, const char *s, size_t len) {
    *p++ = len & 0x7f; memcpy(p, s, len); return p + len;
}
static int h2_static_idx(const char *name, size_t len) {
    static const char *table[] = {
        ":authority",         
        ":method",            
        ":path",              
        ":scheme",            
        "accept",             
        "accept-encoding",    
        "accept-language",    
        "cache-control",      
        "content-length",     
        "content-type",       
        "cookie",             
        "date",               
        "etag",               
        "host",               
        "if-none-match",      
        "if-modified-since",  
        "referer",            
        "user-agent",         
    };
    static const int indices[] = {1,2,4,6,19,16,17,24,28,31,32,33,34,1,41,40,51,58};
    for (int i = 0; i < (int)(sizeof(table)/sizeof(table[0])); i++) {
        if (strlen(table[i]) == len && strncasecmp(name, table[i], len) == 0)
            return indices[i];
    }
    return 0;
}
static int h2_build_headers(uint8_t *out, const char *method, const char *path,
                             const char **hdrs, int nhdrs) {
    uint8_t *p = out;
    if (strcmp(method, "GET") == 0) {
        *p++ = 0x82;
    } else if (strcmp(method, "POST") == 0) {
        *p++ = 0x83;
    } else {
        *p++ = 0x42; p = h2_hpack_str(p, method, strlen(method));
    }
    if (strcmp(path, "/") == 0) {
        *p++ = 0x84;
    } else {
        *p++ = 0x44; p = h2_hpack_str(p, path, strlen(path));
    }
    *p++ = 0x87;
    const char *auth = NULL;
    for (int i = 0; i < nhdrs; i++) {
        if (strncasecmp(hdrs[i], "host", 4) == 0 && (hdrs[i][4] == ':' || hdrs[i][4] == ' ')) {
            const char *v = hdrs[i] + 4;
            while (*v == ':' || *v == ' ') v++;
            auth = v; break;
        }
    }
    if (!auth) auth = "localhost";
    *p++ = 0x41; p = h2_hpack_str(p, auth, strlen(auth));
    for (int i = 0; i < nhdrs; i++) {
        const char *colon = strchr(hdrs[i], ':');
        if (!colon) continue;
        if ((size_t)(colon - hdrs[i]) == 4 && strncasecmp(hdrs[i], "host", 4) == 0) continue;
        const char *val = colon + 1; while (*val == ' ') val++;
        size_t nl = colon - hdrs[i], vl = strlen(val);
        int idx = h2_static_idx(hdrs[i], nl);
        if (idx && idx != 1) {
            *p++ = 0x40 | idx; p = h2_hpack_str(p, val, vl);
        } else {
            *p++ = 0x00; p = h2_hpack_str(p, hdrs[i], nl);
            p = h2_hpack_str(p, val, vl);
        }
    }
    return p - out;
}
static int h2_send_request(planck_conn *c, const char *method, const char *path,
                            const char **hdrs, int nhdrs) {
    uint8_t frame[MAX_BUF], *p = frame;
    int hdr_len = h2_build_headers(p + 9, method, path, hdrs, nhdrs);
    frame[0] = (hdr_len >> 16) & 0xff; frame[1] = (hdr_len >> 8) & 0xff; frame[2] = hdr_len & 0xff;
    frame[3] = 0x01; 
    frame[4] = 0x05; 
    frame[5] = 0; frame[6] = 0; frame[7] = 0; frame[8] = 1; 
    uint8_t ct[MAX_BUF + 32]; 
    int ctlen = tls_encrypt(c, frame, 9 + hdr_len, ct, TLS_CONTENT_APP_DATA, 0x03, 0x03);
    uint8_t rec[5] = { TLS_CONTENT_APP_DATA, 0x03, 0x03 };
    uint16_t rl = htons(ctlen); memcpy(rec + 3, &rl, 2);
    if (full_write(c->fd, rec, 5) || full_write(c->fd, ct, ctlen)) return -1;
    return 0;
}
static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
static int initialized = 0;
void planck_init(void) {
    pthread_mutex_lock(&init_mutex);
    if (!initialized) { srand(time(0) ^ getpid()); initialized = 1; }
    pthread_mutex_unlock(&init_mutex);
}
static int tcp_connect(const char *host, int port) {
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *res;
    char ps[8]; snprintf(ps, sizeof(ps), "%d", port);
    if (getaddrinfo(host, ps, &hints, &res)) return -1;
    int fd = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) { int on = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)); }
    return fd;
}
planck_conn *planck_connect(const char *host, int port, const planck_config *cfg) {
    planck_init();
    int fd = tcp_connect(host, port);
    if (fd < 0) return NULL;
    planck_conn *c = calloc(1, sizeof(*c));
    if (!c) { close(fd); return NULL; }
    c->fd = fd;
    int hs_res = -1;
    if (cfg->tls_version == PLANCK_TLS_13) {
        hs_res = tls13_handshake(c, host, cfg->http_version);
    } else if (cfg->tls_version == PLANCK_TLS_12) {
        hs_res = tls12_handshake(c, host, cfg->http_version);
    } else {
        close(fd); free(c); return NULL;
    }
    if (hs_res == 0) {
        if (cfg->http_version == PLANCK_HTTP_2) {
            const char *preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            uint8_t settings[9] = {0,0,0,4,0,0,0,0,0};
            size_t plain_len = strlen(preface) + sizeof(settings);
            uint8_t plain_buf[MAX_BUF];
            memcpy(plain_buf, preface, strlen(preface));
            memcpy(plain_buf + strlen(preface), settings, sizeof(settings));
            uint8_t ct_buf[MAX_BUF + 32];
            int ctlen = tls_encrypt(c, plain_buf, plain_len, ct_buf, TLS_CONTENT_APP_DATA, 0x03, 0x03);
            uint8_t rec[5] = { TLS_CONTENT_APP_DATA, 0x03, 0x03 };
            uint16_t rl = htons(ctlen); memcpy(rec + 3, &rl, 2);
            if (full_write(c->fd, rec, 5) || full_write(c->fd, ct_buf, ctlen)) {
                close(fd); free(c); return NULL;
            }
            uint8_t got_server_settings = 0;
            uint8_t sent_ack         = 0;
            uint8_t got_ack_from_server = 0;
            while (!got_server_settings || !sent_ack || !got_ack_from_server) {
                uint8_t hdr[5];
                if (recv_all(c->fd, hdr, 5) != 0) {
                    LOG("[H2] recv TLS header failed\n");
                    close(fd); free(c); return NULL;
                }
                uint16_t rlen = (hdr[3] << 8) | hdr[4];
                if (rlen > MAX_BUF) { close(fd); free(c); return NULL; }
                uint8_t buf[MAX_BUF];
                if (recv_all(c->fd, buf, rlen) != 0) {
                    LOG("[H2] recv TLS body failed\n");
                    close(fd); free(c); return NULL;
                }
                uint8_t plain[MAX_BUF];
                int ptlen;
                int used_handshake_keys = 0;
                if (c->tls_version == 13) {
                    ptlen = tls_decrypt_any(c, buf, rlen, plain, hdr[1], hdr[2], &used_handshake_keys);
                } else {
                    ptlen = tls_decrypt_app(c, buf, rlen, plain, hdr[0], hdr[1], hdr[2]);
                }
                if (ptlen < 0) {
                    LOG("[H2] decrypt failed\n");
                    close(fd); free(c); return NULL;
                }
                if (ptlen < 1) {
                    LOG("[H2] decrypt failed (empty)\n");
                    close(fd); free(c); return NULL;
                }
                if (c->tls_version == 13) {
                    uint8_t inner_ct = plain[ptlen - 1];
                    ptlen--;
                    if (inner_ct == TLS_CONTENT_HANDSHAKE && ptlen >= 4) {
                        uint8_t msgtype = plain[0];
                        if (msgtype == 4) {  
                            LOG("[TLS13] drained NewSessionTicket (%d bytes)\n", ptlen);
                            continue;        
                        }
                        LOG("[TLS13] unexpected post-handshake message type %d\n", msgtype);
                        close(fd); free(c); return NULL;
                    }
                    if (inner_ct != TLS_CONTENT_APP_DATA) {
                        LOG("[H2] unexpected inner content type %02x\n", inner_ct);
                        close(fd); free(c); return NULL;
                    }
                }
                const uint8_t *p = plain, *end = plain + ptlen;
                while (p + 9 <= end) {
                    uint32_t flen = (p[0] << 16) | (p[1] << 8) | p[2];
                    uint8_t  type = p[3];
                    uint8_t  flags = p[4];
                    const uint8_t *fdata = p + 9;
                    if (fdata + flen > end) break;
                    if (type == 0x04) {   
                        if (flags & 0x01) {          
                            LOG("[H2] received SETTINGS ACK from server\n");
                            got_ack_from_server = 1;
                        } else {                     
                            LOG("[H2] received server SETTINGS (length %u)\n", flen);
                            got_server_settings = 1;
                            if (!sent_ack) {
                                uint8_t ack[] = {0,0,0, 0x04, 0x01, 0,0,0,0};
                                uint8_t ct_ack[MAX_BUF];
                                int ack_ctlen = tls_encrypt(c, ack, sizeof(ack), ct_ack, TLS_CONTENT_APP_DATA, 0x03, 0x03);
                                uint8_t ack_rec[5] = { TLS_CONTENT_APP_DATA, 0x03, 0x03 };
                                uint16_t ack_rl = htons(ack_ctlen);
                                memcpy(ack_rec + 3, &ack_rl, 2);
                                if (full_write(c->fd, ack_rec, 5) || full_write(c->fd, ct_ack, ack_ctlen)) {
                                    LOG("[H2] failed to send SETTINGS ACK\n");
                                    close(fd); free(c); return NULL;
                                }
                                sent_ack = 1;
                                LOG("[H2] sent SETTINGS ACK\n");
                            }
                        }
                    } else if (type == 0x07) { 
                        LOG("[H2] received GOAWAY, closing\n");
                        close(fd); free(c); return NULL;
                    }
                    p += 9 + flen;
                }
            }
        } 
        return c;
    }
    close(fd); free(c); return NULL;
}
int planck_request(planck_conn *c, const char *method, const char *path,
                   const char **hdrs, int nhdrs,
                   const uint8_t *body, int bodylen,
                   uint8_t *rbuf, int rmax) {
    if (c->http_version == 2) {
        if (h2_send_request(c, method, path, hdrs, nhdrs)) return -1;
        int total_body = 0;
        int stream_closed = 0;
        while (!stream_closed && total_body < rmax) {
            uint8_t rh[5];
            if (recv_all(c->fd, rh, 5)) return -1;
            uint16_t rrl = (rh[3] << 8) | rh[4];
            if (rrl > MAX_BUF) return -1;
            uint8_t enc[MAX_BUF + 32];
            if (recv_all(c->fd, enc, rrl)) return -1;
            uint8_t plain[MAX_BUF];
            int ptlen = tls_decrypt(c, enc, rrl, plain, rh[0], rh[1], rh[2]);
            if (ptlen < 0) return -1;
            if (c->tls_version == 13 && ptlen > 0) {
                ptlen--; 
                while (ptlen > 0 && plain[ptlen - 1] == 0) ptlen--; 
            }
            int p = 0;
            while (p + 9 <= ptlen) {
                uint32_t flen = (plain[p] << 16) | (plain[p+1] << 8) | plain[p+2];
                uint8_t type = plain[p+3];
                uint8_t flags = plain[p+4];
                if (p + 9 + flen > ptlen) break; 
                if (type == 0x00) { 
                    int copy_len = flen;
                    if (total_body + copy_len > rmax) copy_len = rmax - total_body;
                    if (copy_len > 0) {
                        memcpy(rbuf + total_body, plain + p + 9, copy_len);
                        total_body += copy_len;
                    }
                    if (flags & 0x01) stream_closed = 1; 
                } else if (type == 0x01) { 
                    if (flags & 0x01) stream_closed = 1; 
                } else if (type == 0x03 || type == 0x07) { 
                    return -1;
                }
                p += 9 + flen;
            }
        }
        return total_body;
    } else {
        char *req = (char*)c->tx;
        int off = snprintf(req, MAX_BUF, "%s %s HTTP/1.1\r\n", method, path);
        for (int i = 0; i < nhdrs; i++) off += snprintf(req + off, MAX_BUF - off, "%s\r\n", hdrs[i]);
        if (body && bodylen > 0) off += snprintf(req + off, MAX_BUF - off, "Content-Length: %d\r\n", bodylen);
        off += snprintf(req + off, MAX_BUF - off, "\r\n");
        if (body && bodylen > 0) { memcpy(req + off, body, bodylen); off += bodylen; }
        uint8_t ct[MAX_BUF + 32]; 
        int ctlen = tls_encrypt(c, (uint8_t*)req, off, ct, TLS_CONTENT_APP_DATA, 0x03, 0x03);
        uint8_t rec[5] = { TLS_CONTENT_APP_DATA, 0x03, 0x03 };
        uint16_t rl = htons(ctlen); memcpy(rec + 3, &rl, 2);
        if (full_write(c->fd, rec, 5) || full_write(c->fd, ct, ctlen)) return -1;
        uint8_t rh[5]; 
        if (recv_all(c->fd, rh, 5)) return -1;
        uint16_t rrl = (rh[3] << 8) | rh[4];
        uint8_t enc[MAX_BUF + 32]; 
        if (recv_all(c->fd, enc, rrl)) return -1;
        int ptlen = tls_decrypt(c, enc, rrl, rbuf, rh[0], rh[1], rh[2]);
        if (c->tls_version == 13 && ptlen > 0) {
            ptlen--;
            while (ptlen > 0 && rbuf[ptlen - 1] == 0) ptlen--;
        }
        return ptlen;
    }
}
void planck_close(planck_conn *c) { if (c) { close(c->fd); free(c); } }