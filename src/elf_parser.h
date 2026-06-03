#pragma once
#include "elf_types.h"
#include <vector>
#include <string>
#include <unordered_map>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <cstdio>

enum class Arch { ARM32, ARM64, UNKNOWN };

struct FuncInfo {
    uint64_t va;
    uint64_t size;
    uint64_t offset;
    std::string name;
    bool is_thumb;
};

struct SecRange { uint64_t start, end; bool is_plt; };

class ElfParser {
public:
    std::vector<uint8_t> data;
    Arch arch = Arch::UNKNOWN;
    bool is64 = false;

    std::vector<Elf32_Shdr> shdrs32;
    std::vector<Elf64_Shdr> shdrs64;
    std::vector<Elf32_Phdr> phdrs32;
    std::vector<Elf64_Phdr> phdrs64;
    std::string shstrtab;

    void load(const std::string& path) {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) throw std::runtime_error("Cannot open: " + path);
        fseek(f, 0, SEEK_END); size_t sz = ftell(f); fseek(f, 0, SEEK_SET);
        data.resize(sz); fread(data.data(), 1, sz, f); fclose(f);
        parse();
    }
    void save(const std::string& path) {
        FILE* f = fopen(path.c_str(), "wb");
        if (!f) throw std::runtime_error("Cannot write: " + path);
        fwrite(data.data(), 1, data.size(), f); fclose(f);
    }

    void parse() {
        const uint8_t magic[4] = {0x7f,'E','L','F'};
        if (memcmp(data.data(), magic, 4)) throw std::runtime_error("Not ELF");
        is64 = (data[4] == 2);
        uint16_t machine = is64
            ? reinterpret_cast<Elf64_Ehdr*>(data.data())->e_machine
            : reinterpret_cast<Elf32_Ehdr*>(data.data())->e_machine;
        if (machine == EM_ARM)    arch = Arch::ARM32;
        else if (machine == EM_AARCH64) arch = Arch::ARM64;
        else throw std::runtime_error("Not ARM/AArch64");
        snapshot_headers();
    }

    void snapshot_headers() {
        if (!is64) {
            auto* eh = e32();
            shdrs32.clear(); phdrs32.clear();
            for (int i = 0; i < eh->e_shnum; i++) {
                Elf32_Shdr s; memcpy(&s, data.data()+eh->e_shoff+i*sizeof(s), sizeof(s));
                shdrs32.push_back(s);
            }
            for (int i = 0; i < eh->e_phnum; i++) {
                Elf32_Phdr p; memcpy(&p, data.data()+eh->e_phoff+i*sizeof(p), sizeof(p));
                phdrs32.push_back(p);
            }
            if (eh->e_shstrndx < (int)shdrs32.size()) {
                auto& s = shdrs32[eh->e_shstrndx];
                shstrtab.assign((char*)data.data()+s.sh_offset, s.sh_size);
            }
        } else {
            auto* eh = e64();
            shdrs64.clear(); phdrs64.clear();
            for (int i = 0; i < eh->e_shnum; i++) {
                Elf64_Shdr s; memcpy(&s, data.data()+eh->e_shoff+i*sizeof(s), sizeof(s));
                shdrs64.push_back(s);
            }
            for (int i = 0; i < eh->e_phnum; i++) {
                Elf64_Phdr p; memcpy(&p, data.data()+eh->e_phoff+i*sizeof(p), sizeof(p));
                phdrs64.push_back(p);
            }
            if (eh->e_shstrndx < (int)shdrs64.size()) {
                auto& s = shdrs64[eh->e_shstrndx];
                shstrtab.assign((char*)data.data()+s.sh_offset, s.sh_size);
            }
        }
    }

    Elf32_Ehdr* e32() { return reinterpret_cast<Elf32_Ehdr*>(data.data()); }
    Elf64_Ehdr* e64() { return reinterpret_cast<Elf64_Ehdr*>(data.data()); }

    const char* shname32(uint32_t idx) {
        if (idx < shstrtab.size()) return shstrtab.c_str() + idx;
        return "";
    }
    const char* shname64(uint32_t idx) { return shname32(idx); }

    uint64_t offset_to_va(uint64_t off) {
        if (!is64) {
            for (auto& s : shdrs32)
                if (s.sh_addr && off >= s.sh_offset && off < s.sh_offset + s.sh_size)
                    return s.sh_addr + (off - s.sh_offset);
        } else {
            for (auto& s : shdrs64)
                if (s.sh_addr && off >= s.sh_offset && off < s.sh_offset + s.sh_size)
                    return s.sh_addr + (off - s.sh_offset);
        }
        throw std::runtime_error("offset not mapped: " + std::to_string(off));
    }

    uint64_t va_to_offset(uint64_t va) {
        if (!is64) {
            for (auto& s : shdrs32)
                if (s.sh_addr && va>=s.sh_addr && va<s.sh_addr+s.sh_size)
                    return s.sh_offset + (va - s.sh_addr);
        } else {
            for (auto& s : shdrs64)
                if (s.sh_addr && va>=s.sh_addr && va<s.sh_addr+s.sh_size)
                    return s.sh_offset + (va - s.sh_addr);
        }
        throw std::runtime_error("VA not mapped: " + std::to_string(va));
    }

    std::vector<SecRange> exec_ranges() {
        std::vector<SecRange> r;
        if (!is64) {
            for (auto& s : shdrs32) {
                if (!(s.sh_flags & SHF_EXECINSTR)) continue;
                if (!s.sh_addr || !s.sh_size) continue;
                bool plt = strstr(shname32(s.sh_name), ".plt") != nullptr;
                r.push_back({s.sh_addr, s.sh_addr+s.sh_size, plt});
            }
        } else {
            for (auto& s : shdrs64) {
                if (!(s.sh_flags & SHF_EXECINSTR)) continue;
                if (!s.sh_addr || !s.sh_size) continue;
                bool plt = strstr(shname64(s.sh_name), ".plt") != nullptr;
                r.push_back({(uint64_t)s.sh_addr, (uint64_t)(s.sh_addr+s.sh_size), plt});
            }
        }
        return r;
    }

    uint64_t max_va() {
        uint64_t m = 0;
        if (!is64) {
            for (auto& p : phdrs32)
                if (p.p_type == PT_LOAD) m = std::max(m, (uint64_t)(p.p_vaddr+p.p_memsz));
        } else {
            for (auto& p : phdrs64)
                if (p.p_type == PT_LOAD) m = std::max(m, p.p_vaddr+p.p_memsz);
        }
        return m;
    }

    std::vector<FuncInfo> get_functions() {
        std::unordered_map<uint64_t, FuncInfo> dedup;
        if (!is64) collect_funcs32(dedup);
        else       collect_funcs64(dedup);
        std::vector<FuncInfo> v;
        for (auto& [k,f] : dedup) v.push_back(f);
        std::sort(v.begin(), v.end(), [](auto& a, auto& b){ return a.va < b.va; });
        return v;
    }

    uint32_t read32(uint64_t off) { uint32_t v; memcpy(&v, data.data()+off, 4); return v; }
    uint64_t read64(uint64_t off) { uint64_t v; memcpy(&v, data.data()+off, 8); return v; }
    void write32(uint64_t off, uint32_t v) { memcpy(data.data()+off, &v, 4); }
    void write64(uint64_t off, uint64_t v) { memcpy(data.data()+off, &v, 8); }

private:
    void collect_funcs32(std::unordered_map<uint64_t, FuncInfo>& out) {
        auto* eh = e32();
        for (auto& sh : shdrs32) {
            if (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM) continue;
            if (!sh.sh_entsize) continue;
            auto& strsh = shdrs32[sh.sh_link];
            const char* strtab = (char*)data.data() + strsh.sh_offset;
            int n = sh.sh_size / sh.sh_entsize;
            for (int i = 0; i < n; i++) {
                Elf32_Sym sym; memcpy(&sym, data.data()+sh.sh_offset+i*sizeof(sym), sizeof(sym));
                if (ELF32_ST_TYPE(sym.st_info) != STT_FUNC) continue;
                if (sym.st_shndx == SHN_UNDEF || sym.st_size == 0) continue;
                bool thumb = sym.st_value & 1;
                uint32_t va = sym.st_value & ~1u;
                uint64_t foff = 0;
                try { foff = va_to_offset(va); } catch (...) { continue; }
                FuncInfo fi; fi.va=va; fi.size=sym.st_size; fi.offset=foff;
                fi.name = strtab + sym.st_name; fi.is_thumb = thumb;
                out[va] = fi;
            }
        }
    }
    void collect_funcs64(std::unordered_map<uint64_t, FuncInfo>& out) {
        for (auto& sh : shdrs64) {
            if (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM) continue;
            if (!sh.sh_entsize) continue;
            auto& strsh = shdrs64[sh.sh_link];
            const char* strtab = (char*)data.data() + strsh.sh_offset;
            int n = sh.sh_size / sh.sh_entsize;
            for (int i = 0; i < n; i++) {
                Elf64_Sym sym; memcpy(&sym, data.data()+sh.sh_offset+i*(int)sizeof(sym), sizeof(sym));
                if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue;
                if (sym.st_shndx == SHN_UNDEF || sym.st_size == 0) continue;
                uint64_t va = sym.st_value;
                uint64_t foff = 0;
                try { foff = va_to_offset(va); } catch (...) { continue; }
                FuncInfo fi; fi.va=va; fi.size=sym.st_size; fi.offset=foff;
                fi.name = strtab + sym.st_name; fi.is_thumb = false;
                out[va] = fi;
            }
        }
    }
};
