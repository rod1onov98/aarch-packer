#pragma once
#include "elf_types.h"
#include "crypto.h"
#include <vector>
#include <string>
#include <cstring>

class SecRenamer {
public:
    bool skip_init_array = true;

    void run(std::vector<uint8_t>& data, bool is64, uint64_t seed) {
        if (!is64) run32(data, seed);
        else run64(data, seed);
    }

private:
    bool should_skip(const std::string& name) {
        if (skip_init_array) {
            if (name == ".init_array" || name == ".fini_array" || name == ".init" || name == ".fini" || name == ".dynamic" || name == ".got" || name == ".got.plt")
                return true;
        }
        return false;
    }

    void run32(std::vector<uint8_t>& data, uint64_t seed) {
        auto* eh = reinterpret_cast<Elf32_Ehdr*>(data.data());
        if (!eh->e_shstrndx || eh->e_shstrndx >= eh->e_shnum) return;

        Elf32_Shdr shstr_sh;
        memcpy(&shstr_sh, data.data()+eh->e_shoff+eh->e_shstrndx*sizeof(shstr_sh), sizeof(shstr_sh));
        const char* old_strtab = (const char*)data.data() + shstr_sh.sh_offset;

        std::string new_strtab(1, '\0');
        std::vector<uint32_t> new_offsets(eh->e_shnum, 0);
        XorShift64 rng(seed ^ 0x5EC2EA5EC2EAULL);

        for (int i = 0; i < eh->e_shnum; i++) {
            Elf32_Shdr sh; memcpy(&sh, data.data()+eh->e_shoff+i*sizeof(sh), sizeof(sh));
            if (sh.sh_name == 0) { new_offsets[i] = 0; continue; }
            std::string orig(old_strtab + sh.sh_name);
            std::string new_name;
            if (should_skip(orig)) {
                new_name = orig;
            } else {
                new_name = garbage_section_name(seed ^ (uint64_t)i * 0x9E3779B97F4A7C15ULL ^ sh.sh_name);
            }
            new_offsets[i] = (uint32_t)new_strtab.size();
            new_strtab.append(new_name); new_strtab.push_back('\0');
        }

        uint32_t new_shstr_off = (uint32_t)((data.size()+3)&~3u);
        data.resize(new_shstr_off);
        data.insert(data.end(), new_strtab.begin(), new_strtab.end());

        eh = reinterpret_cast<Elf32_Ehdr*>(data.data());
        for (int i = 0; i < eh->e_shnum; i++) {
            Elf32_Shdr sh; memcpy(&sh, data.data()+eh->e_shoff+i*sizeof(sh), sizeof(sh));
            sh.sh_name = new_offsets[i];
            memcpy(data.data()+eh->e_shoff+i*sizeof(sh), &sh, sizeof(sh));
        }
        Elf32_Shdr new_shstr;
        memcpy(&new_shstr, data.data()+eh->e_shoff+eh->e_shstrndx*sizeof(new_shstr), sizeof(new_shstr));
        new_shstr.sh_offset = new_shstr_off;
        new_shstr.sh_size   = (uint32_t)new_strtab.size();
        memcpy(data.data()+eh->e_shoff+eh->e_shstrndx*sizeof(new_shstr), &new_shstr, sizeof(new_shstr));
    }

    void run64(std::vector<uint8_t>& data, uint64_t seed) {
        auto* eh = reinterpret_cast<Elf64_Ehdr*>(data.data());
        if (!eh->e_shstrndx || eh->e_shstrndx >= eh->e_shnum) return;

        Elf64_Shdr shstr_sh;
        memcpy(&shstr_sh, data.data()+eh->e_shoff+eh->e_shstrndx*sizeof(shstr_sh), sizeof(shstr_sh));
        const char* old_strtab = (const char*)data.data() + shstr_sh.sh_offset;

        std::string new_strtab(1, '\0');
        std::vector<uint32_t> new_offsets(eh->e_shnum, 0);
        XorShift64 rng(seed ^ 0x5EC2EA5EC2EAULL);

        for (int i = 0; i < eh->e_shnum; i++) {
            Elf64_Shdr sh; memcpy(&sh, data.data()+eh->e_shoff+i*sizeof(sh), sizeof(sh));
            if (sh.sh_name == 0) { new_offsets[i]=0; continue; }
            std::string orig(old_strtab + sh.sh_name);
            std::string new_name;
            if (should_skip(orig)) {
                new_name = orig;
            } else {
                new_name = garbage_section_name(seed ^ (uint64_t)i * 0x9E3779B97F4A7C15ULL ^ sh.sh_name);
            }
            new_offsets[i] = (uint32_t)new_strtab.size();
            new_strtab.append(new_name); new_strtab.push_back('\0');
        }

        uint64_t new_shstr_off = (data.size()+7)&~7ULL;
        data.resize(new_shstr_off);
        data.insert(data.end(), new_strtab.begin(), new_strtab.end());

        eh = reinterpret_cast<Elf64_Ehdr*>(data.data());
        for (int i = 0; i < eh->e_shnum; i++) {
            Elf64_Shdr sh; memcpy(&sh, data.data()+eh->e_shoff+i*sizeof(sh), sizeof(sh));
            sh.sh_name = new_offsets[i];
            memcpy(data.data()+eh->e_shoff+i*sizeof(sh), &sh, sizeof(sh));
        }
        Elf64_Shdr new_shstr;
        memcpy(&new_shstr, data.data()+eh->e_shoff+eh->e_shstrndx*sizeof(new_shstr), sizeof(new_shstr));
        new_shstr.sh_offset = new_shstr_off;
        new_shstr.sh_size   = new_strtab.size();
        memcpy(data.data()+eh->e_shoff+eh->e_shstrndx*sizeof(new_shstr), &new_shstr, sizeof(new_shstr));
    }
};
