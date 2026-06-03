#pragma once
#include <cstdint>
#include <vector>
#include <cstring>

enum class CallType { ARM_BL, ARM_BLX_IMM, THUMB_BL, THUMB_BLX };

struct CallSite {
    uint32_t file_off;
    uint32_t instr_va;
    uint32_t target_va;
    bool     target_thumb;
    CallType type;
};

inline bool arm32_is_bl   (uint32_t i) { return (i&0x0F000000)==0x0B000000; }
inline bool arm32_is_blx  (uint32_t i) { return (i&0xFE000000)==0xFA000000; }

inline int32_t arm32_bl_offset(uint32_t i) {
    int32_t o = (int32_t)(i&0xFFFFFF);
    if (o&0x800000) o|=0xFF000000;
    return o<<2;
}
inline uint32_t arm32_encode_bl(uint32_t cond, int32_t off) {
    return (cond<<28)|0x0B000000|((uint32_t)(off>>2)&0xFFFFFF);
}
inline bool thumb2_is_bl(uint16_t h1, uint16_t h2) {
    if ((h1&0xF800)!=0xF000) return false;
    return ((h2&0xD000)==0xD000)||((h2&0xD000)==0xC000);
}
inline bool thumb2_is_blx(uint16_t h1, uint16_t h2) {
    return thumb2_is_bl(h1,h2) && ((h2&0xD000)==0xC000);
}
inline int32_t thumb2_bl_offset(uint16_t h1, uint16_t h2) {
    uint32_t S=(h1>>10)&1, I1=!(((h2>>13)&1)^S), I2=!(((h2>>11)&1)^S);
    uint32_t r=(S<<24)|(I1<<23)|(I2<<22)|((uint32_t)(h1&0x3FF)<<12)|((h2&0x7FF)<<1);
    if (r&0x01000000) r|=0xFE000000;
    return (int32_t)r;
}
inline uint32_t thumb2_encode_bl(int32_t off) {
    uint32_t o=(uint32_t)off;
    uint32_t S=(o>>24)&1, I1=(o>>23)&1, I2=(o>>22)&1;
    uint16_t h1=(uint16_t)(0xF000|(S<<10)|((o>>12)&0x3FF));
    uint16_t h2=(uint16_t)(0xD000|((( I1^S^1)&1)<<13)|(((I2^S^1)&1)<<11)|(( o>>1)&0x7FF));
    return ((uint32_t)h2<<16)|h1;
}
inline uint32_t thumb2_encode_blx(int32_t off) {
    uint32_t o=(uint32_t)off;
    uint32_t S=(o>>24)&1, I1=(o>>23)&1, I2=(o>>22)&1;
    uint16_t h1=(uint16_t)(0xF000|(S<<10)|((o>>12)&0x3FF));
    uint16_t h2=(uint16_t)(0xC000|((( I1^S^1)&1)<<13)|(((I2^S^1)&1)<<11)|(((o>>2)&0x3FF)<<1));
    return ((uint32_t)h2<<16)|h1;
}

inline void write_arm32_stub(uint8_t* p, uint32_t target) {
    uint32_t ldr=0xE51FF004u;
    memcpy(p,   &ldr,    4);
    memcpy(p+4, &target, 4);
}

inline std::vector<CallSite> scan_arm32(const uint8_t* code, uint32_t foff, uint32_t fva, uint32_t sz) {
    std::vector<CallSite> r;
    for (uint32_t i=0; i+4<=sz; i+=4) {
        uint32_t ins; memcpy(&ins, code+i, 4);
        uint32_t va=fva+i;
        if (arm32_is_bl(ins)) {
            int32_t o=arm32_bl_offset(ins);
            CallSite cs; cs.file_off=foff+i; cs.instr_va=va;
            cs.target_va=(uint32_t)((int32_t)(va+8)+o)&~1u;
            cs.target_thumb=false; cs.type=CallType::ARM_BL;
            r.push_back(cs);
        } else if (arm32_is_blx(ins)) {
            uint32_t H=(ins>>24)&1;
            int32_t o=arm32_bl_offset(ins)|(H<<1);
            CallSite cs; cs.file_off=foff+i; cs.instr_va=va;
            cs.target_va=(uint32_t)((int32_t)(va+8)+o)&~1u;
            cs.target_thumb=true; cs.type=CallType::ARM_BLX_IMM;
            r.push_back(cs);
        }
    }
    return r;
}

inline std::vector<CallSite> scan_thumb(const uint8_t* code, uint32_t foff, uint32_t fva, uint32_t sz) {
    std::vector<CallSite> r;
    for (uint32_t i=0; i+2<=sz;) {
        uint16_t h1; memcpy(&h1, code+i, 2);
        bool is32=((h1&0xE000)==0xE000)&&((h1&0x1800)!=0);
        if (is32 && i+4<=sz) {
            uint16_t h2; memcpy(&h2, code+i+2, 2);
            if (thumb2_is_bl(h1,h2)) {
                int32_t o=thumb2_bl_offset(h1,h2);
                uint32_t va=fva+i;
                uint32_t pc=(va+4)&~3u;
                bool to_thumb=!thumb2_is_blx(h1,h2);
                CallSite cs; cs.file_off=foff+i; cs.instr_va=va;
                cs.target_va=(uint32_t)((int32_t)pc+o)&~1u;
                cs.target_thumb=to_thumb;
                cs.type=to_thumb?CallType::THUMB_BL:CallType::THUMB_BLX;
                r.push_back(cs);
            }
            i+=4;
        } else { i+=2; }
    }
    return r;
}

inline void patch_arm32_callsite(uint8_t* data, const CallSite& cs, uint32_t stub_va) {
    if (cs.type==CallType::ARM_BL||cs.type==CallType::ARM_BLX_IMM) {
        uint32_t orig; memcpy(&orig, data+cs.file_off, 4);
        uint32_t cond=(orig>>28)&0xF;
        int32_t new_off=(int32_t)stub_va-(int32_t)(cs.instr_va+8);
        uint32_t ni=arm32_encode_bl(cond, new_off);
        memcpy(data+cs.file_off, &ni, 4);
    } else {
        uint32_t pc=(cs.instr_va+4)&~3u;
        int32_t new_off=(int32_t)stub_va-(int32_t)pc;
        uint32_t enc=thumb2_encode_blx(new_off);
        uint16_t h1=(uint16_t)(enc&0xFFFF), h2=(uint16_t)(enc>>16);
        memcpy(data+cs.file_off,   &h1, 2);
        memcpy(data+cs.file_off+2, &h2, 2);
    }
}
