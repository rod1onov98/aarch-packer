#pragma once
#include "elf_types.h"
#include "arch_arm32.h"
#include "crypto.h"
#include <vector>
#include <cstring>
#include <cstdio>
#include <algorithm>

struct GraphBreakerResult {
    uint32_t indirect_table_va;  
    uint32_t indirect_count;   
    uint32_t fake_prologues;  
};

static inline uint32_t gb_rand(uint32_t& state) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

struct IndirectEntry {
    uint32_t call_site_file_off;
    uint32_t call_site_va;
    uint32_t target_va;
    bool     is_thumb_site;
    bool     target_thumb;
    uint32_t table_slot_va;
};

static const uint8_t FAKE_PROLOGUE_ARM32[] = {
    0xF0, 0x41, 0x2D, 0xE9,  // PUSH {R4,R5,R6,R7,R8,LR} ARM32
    0x04, 0xB0, 0x4D, 0xE2,  // SUB  SP, SP, #16  (fake stack alloc)
    0x00, 0x00, 0x00, 0xEA,  // B    +0 
};
static const uint8_t FAKE_PROLOGUE_THUMB[] = {
    0x2D, 0xE9, 0xF0, 0x41,  // PUSH.W {R4,R5,R6,R7,R8,LR} Thumb2
    0x84, 0xB0,              // SUB    SP, #16
    0xFF, 0xE7,              // B      . 
    0x00, 0x00,              // NOP padding
};

class GraphBreaker {
public:
    static uint32_t insert_fake_prologues(std::vector<uint8_t>& data, const std::vector<FuncInfo>& funcs, bool prefer_thumb, uint32_t rng_seed) {
        uint32_t rng = rng_seed;
        uint32_t count = 0;

        for (auto& fi : funcs) {
            if (fi.size < 128) continue;
            if (fi.offset + fi.size > data.size()) continue;
            if ((gb_rand(rng) % 10) != 0) continue;

            uint8_t* code = data.data() + fi.offset;
            uint32_t sz   = (uint32_t)fi.size;

            if (fi.is_thumb) {
                for (uint32_t i = 0; i + 10 < sz; i += 2) {
                    uint16_t hw; memcpy(&hw, code+i, 2);
                    bool is_ret = (hw == 0x4770) || ((hw & 0xFF00) == 0xBD00);
                    if (!is_ret) continue;
                    if (i + 2 + (uint32_t)sizeof(FAKE_PROLOGUE_THUMB) >= sz) continue;
                    memcpy(code + i + 2, FAKE_PROLOGUE_THUMB, sizeof(FAKE_PROLOGUE_THUMB));
                    count++;
                    i += 2 + sizeof(FAKE_PROLOGUE_THUMB) - 2;
                    break;
                }
            } else {
                for (uint32_t i = 0; i + 16 < sz; i += 4) {
                    uint32_t ins; memcpy(&ins, code+i, 4);
                    bool is_ret = (ins == 0xE12FFF1E) || ((ins & 0x0FFF8000) == 0x08BD8000);
                    if (!is_ret) continue;
                    if (i + 4 + (uint32_t)sizeof(FAKE_PROLOGUE_ARM32) >= sz) continue;
                    memcpy(code + i + 4, FAKE_PROLOGUE_ARM32, sizeof(FAKE_PROLOGUE_ARM32));
                    count++;
                    break;
                }
            }
        }
        return count;
    }

    static uint32_t insert_junk_after_branches(std::vector<uint8_t>& data, const std::vector<FuncInfo>& funcs, uint32_t rng_seed) {
        uint32_t rng = rng_seed ^ 0xDEAD;
        uint32_t count = 0;

        static const uint8_t JUNK_THUMB[] = {
            0x4F, 0xF4, 0x80, 0x40,  // MOV.W R0, #0x4000
            0x00, 0xBF,              // NOP
        };

        for (auto& fi : funcs) {
            if (!fi.is_thumb) continue;
            if (fi.size < 128) continue;
            if (fi.offset + fi.size > data.size()) continue;
            if ((gb_rand(rng) % 7) != 0) continue;

            uint8_t* code = data.data() + fi.offset;
            uint32_t sz   = (uint32_t)fi.size;

            for (uint32_t i = 0; i + 8 < sz; i += 2) {
                uint16_t hw; memcpy(&hw, code+i, 2);
                bool is_uncond_b = ((hw & 0xF800) == 0xE000) && (hw != 0xE7FE);
                if (!is_uncond_b) continue;

                int32_t imm = (int32_t)((hw & 0x7FF) << 1);
                if (imm & 0x800) imm |= 0xFFFFF000;
                uint32_t target_off = (uint32_t)((int32_t)(i+4) + imm);
                if (target_off <= i + 2) continue;
                if (i + 2 + sizeof(JUNK_THUMB) >= sz) continue;
                memcpy(code + i + 2, JUNK_THUMB, sizeof(JUNK_THUMB));
                count++;
                i += sizeof(JUNK_THUMB);
                break;
            }
        }
        return count;
    }
};
