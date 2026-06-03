#pragma once
#include <cstdint>
#include <cstring>

struct Elf32_Ehdr { uint8_t e_ident[16]; uint16_t e_type,e_machine; uint32_t e_version,e_entry,e_phoff,e_shoff,e_flags; uint16_t e_ehsize,e_phentsize,e_phnum,e_shentsize,e_shnum,e_shstrndx; };
struct Elf32_Shdr { uint32_t sh_name,sh_type,sh_flags,sh_addr,sh_offset,sh_size,sh_link,sh_info,sh_addralign,sh_entsize; };
struct Elf32_Phdr { uint32_t p_type,p_offset,p_vaddr,p_paddr,p_filesz,p_memsz,p_flags,p_align; };
struct Elf32_Sym  { uint32_t st_name,st_value,st_size; uint8_t st_info,st_other; uint16_t st_shndx; };
struct Elf32_Dyn  { int32_t d_tag; uint32_t d_val; };
struct Elf32_Rel  { uint32_t r_offset,r_info; };
struct Elf32_Rela { uint32_t r_offset,r_info; int32_t r_addend; };

struct Elf64_Ehdr { uint8_t e_ident[16]; uint16_t e_type,e_machine; uint32_t e_version; uint64_t e_entry,e_phoff,e_shoff; uint32_t e_flags; uint16_t e_ehsize,e_phentsize,e_phnum,e_shentsize,e_shnum,e_shstrndx; };
struct Elf64_Shdr { uint32_t sh_name,sh_type; uint64_t sh_flags,sh_addr,sh_offset,sh_size; uint32_t sh_link,sh_info; uint64_t sh_addralign,sh_entsize; };
struct Elf64_Phdr { uint32_t p_type,p_flags; uint64_t p_offset,p_vaddr,p_paddr,p_filesz,p_memsz,p_align; };
struct Elf64_Sym  { uint32_t st_name; uint8_t st_info,st_other; uint16_t st_shndx; uint64_t st_value,st_size; };
struct Elf64_Dyn  { int64_t d_tag; uint64_t d_val; };
struct Elf64_Rel  { uint64_t r_offset,r_info; };
struct Elf64_Rela { uint64_t r_offset,r_info; int64_t r_addend; };

#define ET_DYN 3
#define EM_ARM 40
#define EM_AARCH64 183
#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_DYNSYM 11
#define SHT_DYNAMIC 6
#define SHT_REL 9
#define SHT_RELA 4
#define SHF_WRITE 0x1ULL
#define SHF_ALLOC 0x2ULL
#define SHF_EXECINSTR 0x4ULL
#define STT_FUNC 2
#define SHN_UNDEF 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_PHDR 6
#define PT_NULL 0
#define PF_X 1
#define PF_W 2
#define PF_R 4
#define SHT_HASH   5
#define DT_NULL    0
#define DT_NEEDED  1
#define DT_STRTAB  5
#define DT_SYMTAB 6
#define DT_STRSZ 10
#define DT_SONAME 14
#define DT_INIT 12
#define DT_INIT_ARRAY 25
#define DT_INIT_ARRAYSZ 26

#define ELF32_ST_TYPE(i) ((i)&0xf)
#define ELF64_ST_TYPE(i) ((i)&0xf)
