#pragma once
#include "elf_types.h"
#include "crypto.h"
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <cstdio>

class SymObfuscator {
public:
    std::unordered_map<std::string,std::string> name_map;

    void run(std::vector<uint8_t>& data, bool is64, uint64_t seed) {
        if (!is64) run32(data, seed);
        else       run64(data, seed);
    }

private:
    static bool is_protected(const std::string& s) {
        if (s.empty() || s[0]=='$') return true;
        if (s=="_start"||s=="__bss_start"||s=="_end"||s=="_edata") return true;
        if (s=="JNI_OnLoad"||s=="JNI_OnUnload") return true;
        if (s.size()>3 && s.substr(s.size()-3)==".so") return true;
        return false;
    }

    static void patch_inplace(std::vector<uint8_t>& data, uint32_t sec_off, uint32_t name_off, const std::string& newname) {
        uint32_t pos = sec_off + name_off;
        if (pos >= data.size()) return;
        uint32_t len = 0;
        while (pos+len < data.size() && data[pos+len]) len++;
        if (!len) return;
        for (uint32_t i = 0; i < len; i++)
            data[pos+i] = (i < newname.size()) ? (uint8_t)newname[i] : 'x';
        data[pos+len] = 0;
    }

    static uint32_t elf_hash(const char* name) {
        uint32_t h = 0, g;
        for (; *name; name++) {
            h = (h << 4) + (uint8_t)*name;
            if ((g = h & 0xF0000000u)) h ^= g >> 24;
            h &= ~g;
        }
        return h;
    }

    void rebuild_hash32(std::vector<uint8_t>& data) {
        auto* eh = reinterpret_cast<Elf32_Ehdr*>(data.data());
        uint32_t dynsym_off=0, dynsym_sz=0, dynsym_ent=0;
        uint32_t dynstr_off=0;
        uint32_t hash_off=0, hash_sz=0;
        uint32_t hash_va=0;

        for (int i = 0; i < eh->e_shnum; i++) {
            Elf32_Shdr sh; memcpy(&sh,data.data()+eh->e_shoff+i*sizeof(sh),sizeof(sh));
            if (sh.sh_type==SHT_DYNSYM) {
                dynsym_off=sh.sh_offset; dynsym_sz=sh.sh_size; dynsym_ent=sh.sh_entsize;
                Elf32_Shdr ss; memcpy(&ss,data.data()+eh->e_shoff+sh.sh_link*sizeof(ss),sizeof(ss));
                dynstr_off=ss.sh_offset;
            }
            if (sh.sh_type==SHT_HASH) { hash_off=sh.sh_offset; hash_sz=sh.sh_size; hash_va=sh.sh_addr; }
        }
        if (!dynsym_off || !hash_off || !dynsym_ent) return;

        int nsyms = dynsym_sz / dynsym_ent;
        uint32_t nbuckets = *(uint32_t*)(data.data()+hash_off);
        uint32_t nchain   = *(uint32_t*)(data.data()+hash_off+4);

        memset(data.data()+hash_off+8, 0, (nbuckets+nchain)*4);

        uint32_t* buckets = (uint32_t*)(data.data()+hash_off+8);
        uint32_t* chains  = buckets + nbuckets;

        for (int i = 1; i < nsyms && i < (int)nchain; i++) {
            Elf32_Sym sym; memcpy(&sym,data.data()+dynsym_off+i*dynsym_ent,sizeof(sym));
            if (!sym.st_name) continue;
            const char* name = (const char*)data.data()+dynstr_off+sym.st_name;
            uint32_t h = elf_hash(name) % nbuckets;
            chains[i] = buckets[h];
            buckets[h] = i;
        }
        printf("[*] .hash rebuilt (%u buckets, %u chains)\n", nbuckets, nchain);
    }

    void run32(std::vector<uint8_t>& data, uint64_t seed) {
        auto* eh = reinterpret_cast<Elf32_Ehdr*>(data.data());
        uint64_t ctr = seed;

        for (int si = 0; si < eh->e_shnum; si++) {
            Elf32_Shdr sh;
            memcpy(&sh, data.data()+eh->e_shoff+si*sizeof(sh), sizeof(sh));
            if (sh.sh_type!=SHT_SYMTAB && sh.sh_type!=SHT_DYNSYM) continue;
            if (!sh.sh_entsize) continue;

            Elf32_Shdr strsh;
            memcpy(&strsh, data.data()+eh->e_shoff+sh.sh_link*sizeof(strsh), sizeof(strsh));
            uint32_t str_off = strsh.sh_offset;

            std::unordered_set<uint32_t> done;
            int nsyms = sh.sh_size / sh.sh_entsize;
            for (int i = 0; i < nsyms; i++) {
                Elf32_Sym sym;
                memcpy(&sym, data.data()+sh.sh_offset+i*sizeof(sym), sizeof(sym));
                uint32_t noff = sym.st_name;
                if (!noff || done.count(noff)) continue;
                std::string orig((char*)data.data()+str_off+noff);
                if (orig.empty() || is_protected(orig)) continue;
                if (sym.st_shndx == 0) continue;
                std::string nw = garbage_sym_name(ctr++ ^ noff);
                patch_inplace(data, str_off, noff, nw);
                name_map[orig] = nw;
                done.insert(noff);
            }
        }
        rebuild_hash32(data);
        fix_dynamic32(data);
    }

    void run64(std::vector<uint8_t>& data, uint64_t seed) {
        auto* eh = reinterpret_cast<Elf64_Ehdr*>(data.data());
        uint64_t ctr = seed;
        for (int si = 0; si < eh->e_shnum; si++) {
            Elf64_Shdr sh;
            memcpy(&sh, data.data()+eh->e_shoff+si*sizeof(sh), sizeof(sh));
            if (sh.sh_type!=SHT_SYMTAB && sh.sh_type!=SHT_DYNSYM) continue;
            if (!sh.sh_entsize) continue;
            Elf64_Shdr strsh;
            memcpy(&strsh, data.data()+eh->e_shoff+sh.sh_link*sizeof(strsh), sizeof(strsh));
            uint32_t str_off = (uint32_t)strsh.sh_offset;
            std::unordered_set<uint32_t> done;
            int nsyms = sh.sh_size / sh.sh_entsize;
            for (int i = 0; i < nsyms; i++) {
                Elf64_Sym sym;
                memcpy(&sym, data.data()+sh.sh_offset+i*sizeof(sym), sizeof(sym));
                uint32_t noff = sym.st_name;
                if (!noff || done.count(noff)) continue;
                std::string orig((char*)data.data()+str_off+noff);
                if (orig.empty() || is_protected(orig)) continue;
                if (sym.st_shndx == 0) continue;
                std::string nw = garbage_sym_name(ctr++ ^ noff);
                patch_inplace(data, str_off, noff, nw);
                name_map[orig] = nw;
                done.insert(noff);
            }
        }
        fix_dynamic64(data);
    }

    void fix_dynamic32(std::vector<uint8_t>& data) {
        auto* eh = reinterpret_cast<Elf32_Ehdr*>(data.data());
        for (int i = 0; i < eh->e_shnum; i++) {
            Elf32_Shdr sh; memcpy(&sh,data.data()+eh->e_shoff+i*sizeof(sh),sizeof(sh));
            if (sh.sh_type != SHT_DYNAMIC) continue;
            int nd = sh.sh_size/sizeof(Elf32_Dyn);
            for (int j = 0; j < nd; j++) {
                Elf32_Dyn d; memcpy(&d,data.data()+sh.sh_offset+j*sizeof(d),sizeof(d));
                if (d.d_tag==DT_SONAME) {
                    d.d_tag=21; d.d_val=0;
                    memcpy(data.data()+sh.sh_offset+j*sizeof(d),&d,sizeof(d));
                } else if (d.d_tag==0x6ffffef5u) {
                    d.d_val=0;
                    memcpy(data.data()+sh.sh_offset+j*sizeof(d),&d,sizeof(d));
                }
                if (d.d_tag==0) break;
            }
        }
    }

    void fix_dynamic64(std::vector<uint8_t>& data) {
        auto* eh = reinterpret_cast<Elf64_Ehdr*>(data.data());
        for (int i = 0; i < eh->e_shnum; i++) {
            Elf64_Shdr sh; memcpy(&sh,data.data()+eh->e_shoff+i*sizeof(sh),sizeof(sh));
            if (sh.sh_type != SHT_DYNAMIC) continue;
            int nd = sh.sh_size/sizeof(Elf64_Dyn);
            for (int j = 0; j < nd; j++) {
                Elf64_Dyn d; memcpy(&d,data.data()+sh.sh_offset+j*sizeof(d),sizeof(d));
                if (d.d_tag==DT_SONAME) {
                    d.d_tag=21; d.d_val=0;
                    memcpy(data.data()+sh.sh_offset+j*sizeof(d),&d,sizeof(d));
                } else if (d.d_tag==0x6ffffef5u) {
                    d.d_val=0;
                    memcpy(data.data()+sh.sh_offset+j*sizeof(d),&d,sizeof(d));
                }
                if (d.d_tag==0) break;
            }
        }
    }
};
