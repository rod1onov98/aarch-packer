#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

static inline uint32_t rotl32(uint32_t x,int n){return(x<<n)|(x>>(32-n));}
#define QR(a,b,c,d) \
    a+=b;d^=a;d=rotl32(d,16); \
    c+=d;b^=c;b=rotl32(b,12); \
    a+=b;d^=a;d=rotl32(d, 8); \
    c+=d;b^=c;b=rotl32(b, 7)

static inline void chacha20_block(uint32_t out[16],const uint32_t in[16]){
    uint32_t x[16]; memcpy(x,in,64);
    for(int i=0;i<10;i++){
        QR(x[0],x[4],x[ 8],x[12]); QR(x[1],x[5],x[ 9],x[13]);
        QR(x[2],x[6],x[10],x[14]); QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]); QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[ 8],x[13]); QR(x[3],x[4],x[ 9],x[14]);
    }
    for(int i=0;i<16;i++) out[i]=x[i]+in[i];
}
static inline void chacha20_xor(uint8_t* data,size_t len, const uint8_t key[32],const uint8_t nonce[12],uint32_t counter=0){
    uint32_t state[16];
    state[0]=0x61707865u;state[1]=0x3320646eu;
    state[2]=0x79622d32u;state[3]=0x6b206574u;
    memcpy(state+4,key,32);state[12]=counter;memcpy(state+13,nonce,12);
    uint8_t ks[64];size_t pos=0;
    while(pos<len){
        uint32_t blk[16]; chacha20_block(blk,state);
        memcpy(ks,blk,64); state[12]++;
        size_t chunk=(len-pos<64)?(len-pos):64;
        for(size_t i=0;i<chunk;i++) data[pos+i]^=ks[i];
        pos+=chunk;
    }
}
// jmp tables only btw
static inline uint32_t nbitrev32(uint32_t x){
    x^=0xFFFFFFFFu;
    x=((x&0x55555555u)<<1)|((x&0xAAAAAAAAu)>>1);
    x=((x&0x33333333u)<<2)|((x&0xCCCCCCCCu)>>2);
    x=((x&0x0F0F0F0Fu)<<4)|((x&0xF0F0F0F0u)>>4);
    x=((x&0x00FF00FFu)<<8)|((x&0xFF00FF00u)>>8);
    x=((x&0x0000FFFFu)<<16)|((x&0xFFFF0000u)>>16);
    return x;
}
static inline uint32_t encode_offset(int32_t o){return nbitrev32((uint32_t)o);}

static const uint8_t TEXT_KEY_A[32] = {0x09,0xCC,0x0E,0x29,0x5C,0x8D,0x99,0x13,0x05,0xF6,0xF2,0x3C,0x97,0x9E,0xC5,0xF3,0xE8,0x5A,0x31,0x3F,0xB2,0x1F,0x48,0x8D,0x65,0x59,0x8D,0xCE,0x6B,0x0C,0x26,0x2D};
static const uint8_t TEXT_KEY_B[32] = {0x93,0x9A,0x6E,0x5C,0x33,0xAA,0xF4,0xBE,0x6E,0x4C,0xC4,0x4A,0x47,0x3E,0x83,0x7F,0x8D,0x6B,0xB9,0xE7,0xFB,0x22,0x42,0x99,0xF5,0x53,0x53,0xF9,0xA2,0x2B,0x5F,0x97};
static const uint8_t TEXT_NONCE_A[12] = {0x8E,0xB9,0x1D,0xC2,0x86,0xB2,0xDA,0x6D,0xA7,0x3A,0x9D,0xBB};
static const uint8_t TEXT_NONCE_B[12] = {0x54,0x9A,0x4B,0x56,0x95,0xC5,0x0B,0x30,0x94,0x74,0x8D,0xF9};
static const uint8_t CRIT_KEY_A[32] = {0x47,0xAA,0x74,0x06,0x47,0xD2,0xBF,0x1B,0xFA,0x1E,0xD9,0x70,0x1E,0x26,0x19,0x75,0x2E,0x1D,0x61,0xED,0xA7,0x2C,0x1E,0xB8,0x4B,0x17,0x5C,0x08,0x13,0xC8,0xBB,0x34};
static const uint8_t CRIT_KEY_B[32] = {0x70,0x99,0xED,0x05,0xD0,0x29,0x2C,0x41,0xC3,0x83,0xDC,0x40,0xE3,0xBE,0x67,0xFD,0x49,0x7C,0x25,0x1D,0x48,0xF5,0x0C,0xBE,0x7E,0xB0,0x9F,0x6C,0x86,0xBE,0x65,0x12};
static const uint8_t CRIT_NONCE_A[12] = {0x74,0x3C,0x09,0x7F,0x0D,0x17,0x0E,0x94,0xC2,0x4F,0xBC,0x2C};
static const uint8_t CRIT_NONCE_B[12] = {0x0E,0xF6,0x60,0x77,0x1D,0x2C,0xA1,0xD7,0x6E,0xAD,0xC8,0x77};

static inline void build_key(uint8_t o[32],const uint8_t a[32],const uint8_t b[32]){
    for(int i=0;i<32;i++) o[i]=a[i]^b[i];
}
static inline void build_nonce(uint8_t o[12],const uint8_t a[12],const uint8_t b[12]){
    for(int i=0;i<12;i++) o[i]=a[i]^b[i];
}

static inline void crypt_block(uint8_t* ptr,uint32_t size){
    uint8_t key[32],nonce[12];
    build_key(key,TEXT_KEY_A,TEXT_KEY_B);
    build_nonce(nonce,TEXT_NONCE_A,TEXT_NONCE_B);
    chacha20_xor(ptr,size,key,nonce,0);
}
static inline void crypt_critical(uint8_t* ptr,uint32_t size,uint64_t){
    uint8_t key[32],nonce[12];
    build_key(key,CRIT_KEY_A,CRIT_KEY_B);
    build_nonce(nonce,CRIT_NONCE_A,CRIT_NONCE_B);
    chacha20_xor(ptr,size,key,nonce,1);
}

static const char CHARSET[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
static const int  CSLEN=sizeof(CHARSET)-1;
struct XorShift64{
    uint64_t s;
    XorShift64(uint64_t seed):s(seed?seed:0xdeadbeefcafe1337ULL){}
    uint64_t next(){s^=s<<13;s^=s>>7;s^=s<<17;return s;}
    uint32_t next32(){return(uint32_t)next();}
    std::string name(int len){
        std::string r(len,'_');
        r[0]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"[next32()%52];
        for(int i=1;i<len;i++)r[i]=CHARSET[next32()%CSLEN];
        return r;
    }
};
static inline std::string garbage_section_name(uint64_t s){XorShift64 r(s);return"."+r.name(63);}
static inline std::string garbage_sym_name(uint64_t s){XorShift64 r(s^0xA5A5A5A5A5A5A5A5ULL);int l=32+(r.next32()%96);return"_Z"+r.name(l);}
