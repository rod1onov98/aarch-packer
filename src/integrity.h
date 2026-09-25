#pragma once
#include <cstdint>
#include <cstring>


// WORK STILL IN PROGRESS, integrity not finished.
static inline uint32_t xxhash32(const uint8_t* data, size_t len, uint32_t seed = 0xE00CB63A) {
    static const uint32_t P1=0x9E3779B1,P2=0x85EBCA77,P3=0xC2B2AE3D;
    static const uint32_t P4=0x27D4EB2F,P5=0x165667B1;
    auto rotl=[](uint32_t x,int r){return(x<<r)|(x>>(32-r));};
    auto rnd=[&](uint32_t acc,uint32_t v){return rotl(acc+v*P2,13)*P1;};
    const uint8_t*p=data,*e=data+len; uint32_t h;
    if(len>=16){
        uint32_t v1=seed+P1+P2,v2=seed+P2,v3=seed,v4=seed-P1;
        const uint8_t*lim=e-16;
        do{uint32_t w;
            memcpy(&w,p+ 0,4);v1=rnd(v1,w);
            memcpy(&w,p+ 4,4);v2=rnd(v2,w);
            memcpy(&w,p+ 8,4);v3=rnd(v3,w);
            memcpy(&w,p+12,4);v4=rnd(v4,w);
            p+=16;
        }while(p<=lim);
        h=rotl(v1,1)+rotl(v2,7)+rotl(v3,12)+rotl(v4,18);
    }else h=seed+P5;
    h+=(uint32_t)len;
    while(p+4<=e){uint32_t w;memcpy(&w,p,4);h=rotl(h+w*P3,17)*P4;p+=4;}
    while(p<e){h=rotl(h+(*p++)*P5,11)*P1;}
    h^=h>>15;h*=P2;h^=h>>13;h*=P3;h^=h>>16;
    return h;
}

static const uint32_t INTEGRITY_MAGIC = 0x9740B255;

struct IntegrityRecord { uint32_t magic, n_hashes; };

static const uint32_t CRIT_MAGIC = 0x54495243;
