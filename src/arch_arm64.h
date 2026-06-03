#pragma once
#include <cstdint>
#include <vector>
#include <cstring>

#define A64_BL_MASK   0xFC000000u
#define A64_BL_OPCODE 0x94000000u

inline bool a64_is_bl(uint32_t i) { return (i & A64_BL_MASK) == A64_BL_OPCODE; }

inline int32_t a64_bl_offset(uint32_t i) {
    int32_t imm = (int32_t)(i & 0x3FFFFFF);
    if (imm & 0x2000000) imm |= 0xFC000000;
    return imm << 2;
}
inline uint32_t a64_encode_bl(int32_t off) {
    return A64_BL_OPCODE | (((uint32_t)(off >> 2)) & 0x3FFFFFF);
}

inline void write_a64_stub(uint8_t* p, uint64_t target) {
    uint32_t ldr = 0x58000050u; 
    uint32_t br  = 0xD61F0200u;
    memcpy(p+0, &ldr, 4);
    memcpy(p+4, &br,  4);
    memcpy(p+8, &target, 8);
}
static const uint32_t A64_STUB_SIZE = 16;

struct CallSite64 {
    uint64_t file_off;
    uint64_t instr_va;
    uint64_t target_va;
};

inline std::vector<CallSite64> scan_arm64(const uint8_t* code, uint64_t foff, uint64_t fva, uint64_t sz) {
    std::vector<CallSite64> r;
    for (uint64_t i = 0; i + 4 <= sz; i += 4) {
        uint32_t ins; memcpy(&ins, code+i, 4);
        if (a64_is_bl(ins)) {
            int32_t o = a64_bl_offset(ins);
            uint64_t va = fva + i;
            CallSite64 cs;
            cs.file_off = foff + i;
            cs.instr_va = va;
            cs.target_va = (uint64_t)((int64_t)va + o);
            r.push_back(cs);
        }
    }
    return r;
}

inline void patch_a64_callsite(uint8_t* data, const CallSite64& cs, uint64_t stub_va) {
    int64_t new_off = (int64_t)stub_va - (int64_t)cs.instr_va;
    uint32_t ni = a64_encode_bl((int32_t)new_off);
    memcpy(data + cs.file_off, &ni, 4);
}
