#pragma once
#include "elf_types.h"
#include "crypto.h"
#include "integrity.h"
#include <vector>
#include <cstring>
#include <cstdio>

static const uint32_t STR_HASH_SEED = 0xE00CB63A;
static const uint32_t STRTBL_MAGIC = 0x52545354; // "TSTR"

struct StringTableHdr { uint32_t magic, n_strings; };
struct StringEntry { uint32_t va_off, size, seed, pad; };

static const uint32_t MIN_STR_LEN = 4;
static const uint32_t MAX_STR_LEN = 512;

static inline uint8_t str_key_byte(uint32_t seed, uint32_t idx) {
    uint8_t buf[8]; memcpy(buf,&seed,4); memcpy(buf+4,&idx,4);
    uint32_t h = xxhash32(buf, 8, STR_HASH_SEED);
    return (uint8_t)(h^(h>>8)^(h>>16)^(h>>24));
}
static inline void crypt_string(uint8_t* ptr, uint32_t size, uint32_t seed) {
    for(uint32_t i=0;i<size;i++) ptr[i]^=str_key_byte(seed,i);
}

static inline std::vector<uint8_t> encrypt_strings(
    std::vector<uint8_t>& data, bool is64)
{
    struct RodataSec { uint32_t off,size,addr; };
    std::vector<RodataSec> secs;

    if(!is64){
        auto*eh=reinterpret_cast<Elf32_Ehdr*>(data.data());
        for(int i=0;i<eh->e_shnum;i++){
            Elf32_Shdr sh; memcpy(&sh,data.data()+eh->e_shoff+i*sizeof(sh),sizeof(sh));
            if(!(sh.sh_flags&(uint32_t)SHF_ALLOC))continue;
            if(sh.sh_flags&(uint32_t)SHF_EXECINSTR)continue;
            if(sh.sh_flags&(uint32_t)SHF_WRITE)continue;
            { auto* eh2=(Elf32_Ehdr*)data.data(); Elf32_Shdr ss; memcpy(&ss,data.data()+eh2->e_shoff+eh2->e_shstrndx*sizeof(ss),sizeof(ss)); const char* sn=(const char*)data.data()+ss.sh_offset+sh.sh_name; if(strncmp(sn,".prot_data",10)==0)continue; }
            if(!sh.sh_addr||!sh.sh_size)continue;
            if(sh.sh_type!=SHT_PROGBITS)continue;
            secs.push_back({sh.sh_offset,sh.sh_size,sh.sh_addr});
        }
    }else{
        auto*eh=reinterpret_cast<Elf64_Ehdr*>(data.data());
        for(int i=0;i<eh->e_shnum;i++){
            Elf64_Shdr sh; memcpy(&sh,data.data()+eh->e_shoff+i*sizeof(sh),sizeof(sh));
            if(!(sh.sh_flags&SHF_ALLOC))continue;
            if(sh.sh_flags&SHF_EXECINSTR)continue;
            if(sh.sh_flags&SHF_WRITE)continue;
            { auto* eh2=(Elf64_Ehdr*)data.data(); Elf64_Shdr ss; memcpy(&ss,data.data()+eh2->e_shoff+eh2->e_shstrndx*sizeof(ss),sizeof(ss)); const char* sn=(const char*)data.data()+ss.sh_offset+sh.sh_name; if(strncmp(sn,".prot_data",10)==0)continue; }
            if(!sh.sh_addr||!sh.sh_size)continue;
            if(sh.sh_type!=SHT_PROGBITS)continue;
            secs.push_back({(uint32_t)sh.sh_offset,(uint32_t)sh.sh_size,(uint32_t)sh.sh_addr});
        }
    }

    printf("[*] Found %zu read-only sections for string encryption\n",secs.size());

    std::vector<StringEntry> entries;
    uint32_t seed_ctr = 0xC0FFEE01;

    for(auto&sec:secs){
        const uint8_t*ptr=data.data()+sec.off;
        uint32_t i=0;
        while(i<sec.size){
            if(ptr[i]>=0x20&&ptr[i]<0x7F){
                uint32_t start=i;
                while(i<sec.size&&ptr[i]!=0)i++;
                uint32_t slen=i-start+1;
                if(slen>=MIN_STR_LEN&&slen<=MAX_STR_LEN){
                    uint32_t va_off=sec.addr+start;
                    uint32_t seed=seed_ctr++^va_off^0xF00DCAFE;
                    StringEntry e; e.va_off=va_off; e.size=slen; e.seed=seed; e.pad=0;
                    entries.push_back(e);
                    crypt_string(data.data()+sec.off+start,slen-1,seed);
                }
                i++;
            }else i++;
        }
    }

    printf("[*] Encrypted %zu strings\n",entries.size());

    uint32_t bsz=sizeof(StringTableHdr)+(uint32_t)(entries.size()*sizeof(StringEntry));
    std::vector<uint8_t> blob(bsz,0);
    StringTableHdr hdr; hdr.magic=STRTBL_MAGIC; hdr.n_strings=(uint32_t)entries.size();
    memcpy(blob.data(),&hdr,sizeof(hdr));
    for(size_t i=0;i<entries.size();i++)
        memcpy(blob.data()+sizeof(hdr)+i*sizeof(StringEntry),&entries[i],sizeof(StringEntry));
    return blob;
}
