#pragma once
#include "elf_parser.h"
#include "arch_arm32.h"
#include "arch_arm64.h"
#include "crypto.h"
#include "integrity.h"
#include "string_enc.h"
#include "graph_breaker.h"
#include "sym_obfuscator.h"
#include "sec_renamer.h"
#include "config.h"
#include <vector>
#include <unordered_map>
#include <cstdio>
#include <cstring>
#include <algorithm>

static inline uint64_t aup64(uint64_t v,uint64_t a){return(v+a-1)&~(a-1);}
static inline uint32_t aup32(uint32_t v,uint32_t a){return(v+a-1)&~(a-1);}

static const uint32_t PROT_MAGIC_RAW  = 0x544F5250u;
static const uint32_t PROT_MAGIC_MASK = 0xC01EBA42u;
static inline uint32_t obf_magic(uint32_t m){return m^PROT_MAGIC_MASK;}

class Protector {
public:
    bool       verbose = false;
    ProtConfig cfg;

    void run(const std::string& in, const std::string& out) {
        ElfParser elf;
        printf("[*] Loading %s\n", in.c_str());
        elf.load(in);
        printf("[*] Arch: %s\n", elf.arch==Arch::ARM64?"ARM64":"ARM32");
        cfg.print();
        if (elf.arch==Arch::ARM64) run64(elf);
        else                        run32(elf);
        printf("[*] Saving %s\n", out.c_str());
        elf.save(out);
        printf("[+] Done! %zu bytes\n", elf.data.size());
    }

private:
    void resolve_skip_sizes(ElfParser& elf) {
        auto funcs = elf.get_functions();
        std::unordered_map<uint64_t,uint32_t> va_size;
        std::unordered_map<std::string,uint64_t> name_va;
        for (auto& fi : funcs) {
            va_size[fi.va] = (uint32_t)fi.size;
            if (!fi.name.empty()) name_va[fi.name] = fi.va;
        }

        uint64_t end_marker_va = 0;
        auto it_end = name_va.find("_prot_init_end");
        if (it_end != name_va.end()) end_marker_va = it_end->second;
        if (!end_marker_va) {
            for (auto& fi : funcs) {
                if (fi.name.find("prot_init_end") != std::string::npos) {
                    end_marker_va = fi.va;
                    break;
                }
            }
        }

        for (auto& s : cfg.skip_funcs) {
            if (s.va && s.size) {
                printf("[*] Skip '%s': VA=0x%llx size=%u (from config)\n", s.name.c_str(),(unsigned long long)s.va,s.size);
                continue;
            }

            if (!s.va) {
                PatternResult pr = {0,0};
                if (elf.arch == Arch::ARM32)
                    pr = find_by_pattern(elf.data, PROT_INIT_PATTERN_ARM32, PROT_INIT_PATTERN_ARM32_LEN);
                if (pr.file_off) {
                    try { s.va = elf.offset_to_va(pr.file_off); }
                    catch (...) { s.va = pr.file_off; }
                    printf("[*] Pattern resolved VA for '%s': 0x%llx\n", s.name.c_str(),(unsigned long long)s.va);
                }
            }

            if (!s.va) {
                s.size = 512;
                printf("[!] '%s': VA not found, skipping 512 bytes at 0\n", s.name.c_str());
                continue;
            }

            if (!s.size) {
                auto it = va_size.find(s.va);
                if (it != va_size.end() && it->second > 16) {
                    s.size = it->second;
                    printf("[*] Skip '%s': VA=0x%llx size=%u (symtab)\n", s.name.c_str(),(unsigned long long)s.va,s.size);
                    continue;
                }
            }

            if (!s.size && end_marker_va && end_marker_va > s.va) {
                s.size = (uint32_t)(end_marker_va - s.va);
                printf("[*] Skip '%s': VA=0x%llx size=%u (end marker)\n", s.name.c_str(),(unsigned long long)s.va,s.size);
                continue;
            }

            if (!s.size) {
                s.size = 512;
                printf("[!] Skip '%s': VA=0x%llx size=512 (default, " "add _prot_init_end marker for accuracy)\n", s.name.c_str(),(unsigned long long)s.va);
            }
        }
    }

    struct SkipRange { uint32_t off, size; };

    std::vector<SkipRange> get_skips(ElfParser& elf, uint32_t sec_off, uint32_t sec_size) {
        std::vector<SkipRange> r;
        for (auto& s : cfg.skip_funcs) {
            if (!s.va || !s.size) continue;
            uint64_t foff=0;
            try{foff=elf.va_to_offset(s.va);}catch(...){continue;}
            uint32_t fo=(uint32_t)foff;
            uint32_t se=sec_off+sec_size, fe=fo+s.size;
            if(fo>=se||fe<=sec_off) continue;
            uint32_t cs=(fo<sec_off)?sec_off:fo;
            uint32_t ce=(fe>se)?se:fe;
            r.push_back({cs,ce-cs});
        }
        std::sort(r.begin(),r.end(),[](auto&a,auto&b){return a.off<b.off;});
        return r;
    }

    void encrypt_with_skips(ElfParser& elf, uint32_t sec_off, uint32_t sec_size, const std::vector<SkipRange>& skips) {
        uint32_t cur=sec_off, end=sec_off+sec_size;
        for(auto&sk:skips){
            if(cur<sk.off) crypt_block(elf.data.data()+cur,sk.off-cur);
            cur=sk.off+sk.size;
        }
        if(cur<end) crypt_block(elf.data.data()+cur,end-cur);
    }

    void run32(ElfParser& elf) {
        resolve_skip_sizes(elf);

        auto funcs  = elf.get_functions();
        auto ranges = elf.exec_ranges();
        printf("[*] Found %zu functions\n", funcs.size());

        auto is_int=[&](uint64_t va){
            for(auto&r:ranges) if(va>=r.start&&va<r.end) return !r.is_plt;
            return false;
        };

        std::vector<CallSite> calls;
        for(auto&fi:funcs){
            if(!fi.size||fi.offset+fi.size>elf.data.size()) continue;
            auto s=fi.is_thumb?scan_thumb(elf.data.data()+fi.offset,(uint32_t)fi.offset,(uint32_t)fi.va,(uint32_t)fi.size):scan_arm32(elf.data.data()+fi.offset,(uint32_t)fi.offset,(uint32_t)fi.va,(uint32_t)fi.size);
            for(auto&cs:s) if(is_int(cs.target_va)) calls.push_back(cs);
        }
        printf("[*] Found %zu call sites\n", calls.size());

        struct ESec{uint32_t off,size,addr;};
        auto get_sh_name32 = [&](const Elf32_Shdr& sh) -> std::string {
            auto* eh2 = elf.e32();
            Elf32_Shdr strsh; memcpy(&strsh,elf.data.data()+eh2->e_shoff+eh2->e_shstrndx*sizeof(strsh),sizeof(strsh));
            const char* s = (const char*)elf.data.data()+strsh.sh_offset+sh.sh_name;
            return std::string(s);
        };
        std::vector<ESec> esecs;
        {
            auto xr=elf.exec_ranges(); auto*eh=elf.e32();
            for(int i=0;i<eh->e_shnum;i++){
                Elf32_Shdr sh; memcpy(&sh,elf.data.data()+eh->e_shoff+i*sizeof(sh),sizeof(sh));
                if(!(sh.sh_flags&SHF_EXECINSTR)||!sh.sh_addr||!sh.sh_size) continue;
                { std::string sn=get_sh_name32(sh); if(sn==".prot_text"||sn==".prot"||sn==".prot_data"){printf("[*] Auto-skip '%s'\n",sn.c_str());continue;} }
                bool plt=false;
                  for(auto&r:xr) if(r.is_plt&&sh.sh_addr>=r.start&&sh.sh_addr<r.end){plt=true;break;}
                if(!plt) esecs.push_back({sh.sh_offset,sh.sh_size,sh.sh_addr});
            }
        }

        struct IEntry{uint32_t va_off,hash;};
        std::vector<IEntry> ihashes;
        if(cfg.encrypt_text){
            for(auto&es:esecs){
                uint32_t h=xxhash32(elf.data.data()+es.off,es.size);
                ihashes.push_back({es.addr,h});
                printf("[*] Integrity hash VA=0x%x: 0x%08x\n",es.addr,h);
            }
        }

        uint64_t new_va  =aup64(elf.max_va(),0x1000);
        uint64_t new_foff=aup64(elf.data.size(),0x1000);
        size_t   N=calls.size();

        struct Reg32{uint32_t va_off,size;};
        std::vector<Reg32> enc_regs;
        for(auto&es:esecs) enc_regs.push_back({es.addr,es.size});

        uint32_t hdr_sz   =8+(uint32_t)(enc_regs.size()*8);
        uint32_t table_off=hdr_sz;
        uint32_t stubs_off=table_off+(uint32_t)(N*8);
        uint32_t integ_off=aup32(stubs_off+(uint32_t)(N*8),4);
        uint32_t integ_sz =8+(uint32_t)(ihashes.size()*8);
        uint32_t prot_sz  =aup32(integ_off+integ_sz,4);

        std::vector<uint8_t> blob(prot_sz,0);
        uint32_t magic=cfg.obfuscate_magic?obf_magic(PROT_MAGIC_RAW):PROT_MAGIC_RAW;
        uint32_t nreg=(uint32_t)enc_regs.size();
        memcpy(blob.data(),  &magic,4);
        memcpy(blob.data()+4,&nreg, 4);
        for(size_t ri=0;ri<enc_regs.size();ri++){
            memcpy(blob.data()+8+ri*8,  &enc_regs[ri].va_off,4);
            memcpy(blob.data()+8+ri*8+4,&enc_regs[ri].size,  4);
        }

        std::vector<uint32_t> stub_vas(N);
        for(size_t i=0;i<N;i++){
            uint32_t sv=(uint32_t)(new_va+stubs_off+i*8);
            uint32_t ev=(uint32_t)(new_va+table_off+4*i);
            stub_vas[i]=sv;
            uint32_t enc=encode_offset((int32_t)(sv-ev));
            memcpy(blob.data()+table_off+4*i,  &enc,4);
            uint32_t tgt=(uint32_t)calls[i].target_va|(calls[i].target_thumb?1u:0u);
            memcpy(blob.data()+table_off+N*4+4*i,&tgt,4);
            write_arm32_stub(blob.data()+stubs_off+i*8,tgt);
        }

        uint32_t imag=INTEGRITY_MAGIC,nh=(uint32_t)ihashes.size();
        memcpy(blob.data()+integ_off,  &imag,4);
        memcpy(blob.data()+integ_off+4,&nh,  4);
        for(size_t i=0;i<ihashes.size();i++){
            memcpy(blob.data()+integ_off+8+i*8,  &ihashes[i].va_off,4);
            memcpy(blob.data()+integ_off+8+i*8+4,&ihashes[i].hash,  4);
        }

        {
            auto*eh2=elf.e32();
            for(int i=0;i<eh2->e_shnum;i++){
                Elf32_Shdr sh; memcpy(&sh,elf.data.data()+eh2->e_shoff+i*sizeof(sh),sizeof(sh));
                if(sh.sh_type!=14) continue;
                for(uint32_t j=0;j<sh.sh_size/4;j++){
                    uint32_t val; memcpy(&val,elf.data.data()+sh.sh_offset+j*4,4);
                    uint32_t va=val&~1u;
                    for(auto&sf:cfg.skip_funcs){
                        if(sf.va&&va==(uint32_t)sf.va&&!(val&1)){
                            val|=1;
                            memcpy(elf.data.data()+sh.sh_offset+j*4,&val,4);
                            printf("[*] Set Thumb bit for '%s' in .init_array\n",sf.name.c_str());
                        }
                    }
                }
            }
        }

        printf("[*] Graph breaker...\n");
        uint32_t fp=GraphBreaker::insert_fake_prologues(elf.data,funcs,true,(uint32_t)cfg.name_seed);
        uint32_t jb=GraphBreaker::insert_junk_after_branches(elf.data,funcs,(uint32_t)(cfg.name_seed>>32));
        printf("[*]   %u fake prologues, %u junk blocks\n",fp,jb);

        std::vector<uint8_t> str_blob;
        if(cfg.encrypt_text){
            printf("[*] Encrypting strings...\n");
            str_blob=encrypt_strings(elf.data,false);
        }

        printf("[*] Patching %zu call sites...\n",N);
        for(size_t i=0;i<N;i++)
            patch_arm32_callsite(elf.data.data(),calls[i],stub_vas[i]);

        if(cfg.encrypt_text){
            printf("[*] Encrypting sections...\n");
            for(auto&es:esecs){
                printf("[*]   off=0x%x size=0x%x\n",es.off,es.size);
                auto skips=get_skips(elf,es.off,es.size);
                for(auto&sk:skips)
                    printf("[*]   Skip off=0x%x size=%u\n",sk.off,sk.size);
                encrypt_with_skips(elf,es.off,es.size,skips);
            }
        }

        if(!cfg.critical_funcs.empty()){
            printf("[*] Critical functions...\n");
            for(auto&cf:cfg.critical_funcs){
                uint32_t sz=cf.size;
                if(!sz) for(auto&fi:funcs) if(fi.va==cf.va){sz=(uint32_t)fi.size;break;}
                if(!sz){printf("[!] %s: unknown size\n",cf.name.c_str());continue;}
                uint64_t foff=0;
                try{foff=elf.va_to_offset(cf.va);}catch(...){continue;}
                crypt_block(elf.data.data()+foff,sz);
                crypt_critical(elf.data.data()+foff,sz,cf.va);
                printf("[*]   %s @ 0x%llx size=%u\n", cf.name.c_str(),(unsigned long long)cf.va,sz);
            }
        }

        if(!str_blob.empty()){
            uint32_t pad=aup32((uint32_t)blob.size(),4)-(uint32_t)blob.size();
            blob.resize(blob.size()+pad,0);
            blob.insert(blob.end(),str_blob.begin(),str_blob.end());
            printf("[*] String table: %zu bytes\n",str_blob.size());
        }

        append32(elf,blob,(uint32_t)new_foff,(uint32_t)new_va);

        elf.snapshot_headers();
        if(cfg.rename_sections){
            printf("[*] Renaming sections...\n");
            SecRenamer sr; sr.skip_init_array=cfg.skip_init_array;
            sr.run(elf.data,false,cfg.name_seed);
        }
        elf.snapshot_headers();
        if(cfg.rename_symbols){
            printf("[*] Renaming symbols...\n");
            SymObfuscator so; so.run(elf.data,false,cfg.name_seed^0xDEADC0DE);
            printf("[*] Renamed %zu symbols\n",so.name_map.size());
        }
    }

    void run64(ElfParser& elf) {
        resolve_skip_sizes(elf);

        auto funcs  = elf.get_functions();
        auto ranges = elf.exec_ranges();
        printf("[*] Found %zu functions\n", funcs.size());

        auto is_int=[&](uint64_t va){
            for(auto&r:ranges) if(va>=r.start&&va<r.end) return !r.is_plt;
            return false;
        };

        std::vector<CallSite64> calls;
        for(auto&fi:funcs){
            if(!fi.size||fi.offset+fi.size>elf.data.size()) continue;
            auto s=scan_arm64(elf.data.data()+fi.offset,fi.offset,fi.va,fi.size);
            for(auto&cs:s) if(is_int(cs.target_va)) calls.push_back(cs);
        }
        printf("[*] Found %zu call sites\n",calls.size());

        struct ESec64{uint64_t off,size,addr;};
        auto get_sh_name64 = [&](const Elf64_Shdr& sh) -> std::string {
            auto* eh2 = elf.e64();
            Elf64_Shdr strsh; memcpy(&strsh,elf.data.data()+eh2->e_shoff+eh2->e_shstrndx*sizeof(strsh),sizeof(strsh));
            const char* s = (const char*)elf.data.data()+strsh.sh_offset+sh.sh_name;
            return std::string(s);
        };
        std::vector<ESec64> esecs;
        {
            auto xr=elf.exec_ranges(); auto*eh=elf.e64();
            for(int i=0;i<eh->e_shnum;i++){
                Elf64_Shdr sh; memcpy(&sh,elf.data.data()+eh->e_shoff+i*sizeof(sh),sizeof(sh));
                if(!(sh.sh_flags&SHF_EXECINSTR)||!sh.sh_addr||!sh.sh_size) continue;
                { std::string sn=get_sh_name64(sh); if(sn==".prot_text"||sn==".prot"||sn==".prot_data"){printf("[*] Auto-skip '%s'\n",sn.c_str());continue;} }
                bool plt=false;
                for(auto&r:xr) if(r.is_plt&&(uint64_t)sh.sh_addr>=r.start&&(uint64_t)sh.sh_addr<r.end){plt=true;break;}
                if(!plt) esecs.push_back({(uint64_t)sh.sh_offset,(uint64_t)sh.sh_size,(uint64_t)sh.sh_addr});
            }
        }

        struct IEntry64{uint64_t va_off;uint32_t hash,pad;};
        std::vector<IEntry64> ihashes;
        if(cfg.encrypt_text)
            for(auto&es:esecs){
                uint32_t h=xxhash32(elf.data.data()+(size_t)es.off,(size_t)es.size);
                ihashes.push_back({es.addr,h,0});
                printf("[*] Integrity hash VA=0x%lx: 0x%08x\n",(unsigned long)es.addr,h);
            }

        uint64_t new_va  =aup64(elf.max_va(),0x1000);
        uint64_t new_foff=aup64(elf.data.size(),0x1000);
        size_t   N=calls.size();

        struct Reg64{uint64_t va_off,size;};
        std::vector<Reg64> enc_regs;
        for(auto&es:esecs) enc_regs.push_back({es.addr,es.size});

        uint64_t hdr_sz   =8+enc_regs.size()*16;
        uint64_t table_off=hdr_sz;
        uint64_t stubs_off=table_off+N*16;
        uint64_t integ_off=aup64(stubs_off+N*A64_STUB_SIZE,8);
        uint64_t integ_sz =8+ihashes.size()*16;
        uint64_t prot_sz  =aup64(integ_off+integ_sz,8);

        std::vector<uint8_t> blob((size_t)prot_sz,0);
        uint32_t magic=cfg.obfuscate_magic?obf_magic(PROT_MAGIC_RAW):PROT_MAGIC_RAW;
        uint32_t nreg=(uint32_t)enc_regs.size();
        memcpy(blob.data(),  &magic,4);
        memcpy(blob.data()+4,&nreg, 4);
        for(size_t ri=0;ri<enc_regs.size();ri++){
            memcpy(blob.data()+8+ri*16,  &enc_regs[ri].va_off,8);
            memcpy(blob.data()+8+ri*16+8,&enc_regs[ri].size,  8);
        }
        std::vector<uint64_t> stub_vas(N);
        for(size_t i=0;i<N;i++){
            uint64_t sv=new_va+stubs_off+i*A64_STUB_SIZE;
            stub_vas[i]=sv;
            uint32_t lo=encode_offset((int32_t)((sv-(new_va+table_off+8*i))&0xFFFFFFFF));
            uint32_t hi=encode_offset((int32_t)((sv-(new_va+table_off+8*i))>>32));
            memcpy(blob.data()+table_off+8*i,  &lo,4);
            memcpy(blob.data()+table_off+8*i+4,&hi,4);
            uint64_t tgt=calls[i].target_va;
            memcpy(blob.data()+table_off+N*8+8*i,&tgt,8);
            write_a64_stub(blob.data()+(size_t)stubs_off+i*A64_STUB_SIZE,tgt);
        }
        uint32_t imag=INTEGRITY_MAGIC,nh=(uint32_t)ihashes.size();
        memcpy(blob.data()+integ_off,  &imag,4);
        memcpy(blob.data()+integ_off+4,&nh,  4);
        for(size_t i=0;i<ihashes.size();i++){
            memcpy(blob.data()+integ_off+8+i*16,  &ihashes[i].va_off,8);
            memcpy(blob.data()+integ_off+8+i*16+8,&ihashes[i].hash,  4);
        }

        printf("[*] Graph breaker...\n");
        uint32_t fp=GraphBreaker::insert_fake_prologues(elf.data,funcs,false,(uint32_t)cfg.name_seed);
        printf("[*]   %u fake prologues\n",fp);

        std::vector<uint8_t> str_blob;
        if(cfg.encrypt_text){
            printf("[*] Encrypting strings...\n");
            str_blob=encrypt_strings(elf.data,true);
        }

        printf("[*] Patching %zu call sites...\n",N);
        for(size_t i=0;i<N;i++)
            patch_a64_callsite(elf.data.data(),calls[i],stub_vas[i]);

        if(cfg.encrypt_text){
            printf("[*] Encrypting sections...\n");
            for(auto&es:esecs){
                printf("[*]   off=0x%lx size=0x%lx\n",(unsigned long)es.off,(unsigned long)es.size);
                crypt_block(elf.data.data()+(size_t)es.off,(uint32_t)es.size);
            }
        }

        if(!cfg.critical_funcs.empty())
            for(auto&cf:cfg.critical_funcs){
                uint32_t sz=cf.size;
                if(!sz) for(auto&fi:funcs) if(fi.va==cf.va){sz=(uint32_t)fi.size;break;}
                if(!sz) continue;
                uint64_t foff=0;
                try{foff=elf.va_to_offset(cf.va);}catch(...){continue;}
                crypt_block(elf.data.data()+foff,sz);
                crypt_critical(elf.data.data()+foff,sz,cf.va);
            }

        if(!str_blob.empty()){
            uint64_t pad=aup64((uint64_t)blob.size(),8)-(uint64_t)blob.size();
            blob.resize(blob.size()+pad,0);
            blob.insert(blob.end(),str_blob.begin(),str_blob.end());
            printf("[*] String table: %zu bytes\n",str_blob.size());
        }

        append64(elf,blob,new_foff,new_va);

        {
            auto*eh2=elf.e64();
            uint64_t prot_init_va = 0;
            for(int si=0;si<eh2->e_shnum&&!prot_init_va;si++){
                Elf64_Shdr sh; memcpy(&sh,elf.data.data()+eh2->e_shoff+si*sizeof(sh),sizeof(sh));
                if((sh.sh_type!=2&&sh.sh_type!=11)||!sh.sh_entsize) continue;
                Elf64_Shdr strsh; memcpy(&strsh,elf.data.data()+eh2->e_shoff+sh.sh_link*sizeof(strsh),sizeof(strsh));
                for(uint64_t j=0;j<sh.sh_size/sh.sh_entsize;j++){
                    Elf64_Sym sym; memcpy(&sym,elf.data.data()+sh.sh_offset+j*sh.sh_entsize,sizeof(sym));
                    if(!sym.st_value) continue;
                    const char* nm=(const char*)elf.data.data()+strsh.sh_offset+sym.st_name;
                    if(strcmp(nm,"_prot_init")==0){prot_init_va=sym.st_value;break;}
                }
            }

            if(!prot_init_va){
                uint64_t prot_begin_va=0, prot_text_va=0, prot_text_sz=0;
                for(int si=0;si<eh2->e_shnum;si++){
                    Elf64_Shdr sh; memcpy(&sh,elf.data.data()+eh2->e_shoff+si*sizeof(sh),sizeof(sh));
                    if(sh.sh_type==2||sh.sh_type==11){
                        if(!sh.sh_entsize) continue;
                        Elf64_Shdr strsh; memcpy(&strsh,elf.data.data()+eh2->e_shoff+sh.sh_link*sizeof(strsh),sizeof(strsh));
                        for(uint64_t j=0;j<sh.sh_size/sh.sh_entsize;j++){
                            Elf64_Sym sym; memcpy(&sym,elf.data.data()+sh.sh_offset+j*sh.sh_entsize,sizeof(sym));
                            if(!sym.st_value) continue;
                            const char* nm=(const char*)elf.data.data()+strsh.sh_offset+sym.st_name;
                            if(strcmp(nm,"_prot_begin")==0) prot_begin_va=sym.st_value;
                        }
                    }
                    {Elf64_Shdr strsh2; memcpy(&strsh2,elf.data.data()+eh2->e_shoff+eh2->e_shstrndx*sizeof(strsh2),sizeof(strsh2));
                    const char* sn=(const char*)elf.data.data()+strsh2.sh_offset+sh.sh_name;
                    if(strcmp(sn,".prot_text")==0){prot_text_va=sh.sh_addr;prot_text_sz=sh.sh_size;}}
                }
                if(prot_text_va) prot_init_va=prot_text_va;
                if(prot_init_va) printf("[*] _prot_init VA inferred from .prot_text: 0x%llx\n",(unsigned long long)prot_init_va);
            }

            if(prot_init_va){
                for(int si=0;si<eh2->e_shnum;si++){
                    Elf64_Shdr sh; memcpy(&sh,elf.data.data()+eh2->e_shoff+si*sizeof(sh),sizeof(sh));
                    if(sh.sh_type!=14) continue;
                    for(uint64_t j=0;j<sh.sh_size/8;j++){
                        uint64_t val; memcpy(&val,elf.data.data()+sh.sh_offset+j*8,8);
                        if(val==0){
                            memcpy(elf.data.data()+sh.sh_offset+j*8,&prot_init_va,8);
                            printf("[*] Patched .init_array[%llu] = 0x%llx (_prot_init)\n",(unsigned long long)j,(unsigned long long)prot_init_va);
                            break;
                        }
                    }
                    break;
                }
            } else {
                printf("[!] _prot_init not found in symtab\n");
            }
        }

        elf.snapshot_headers();
        if(cfg.rename_sections){SecRenamer sr;sr.skip_init_array=cfg.skip_init_array;sr.run(elf.data,true,cfg.name_seed);}
        elf.snapshot_headers();
        if(cfg.rename_symbols){SymObfuscator so;so.run(elf.data,true,cfg.name_seed^0xDEADC0DE);printf("[*] Renamed %zu symbols\n",so.name_map.size());}
    }

    void append32(ElfParser& elf,const std::vector<uint8_t>& blob,uint32_t foff,uint32_t va){
        auto*e0=elf.e32();
        uint32_t oph=e0->e_phoff,osh=e0->e_shoff;
        uint16_t opn=e0->e_phnum,osn=e0->e_shnum,osx=e0->e_shstrndx;
        std::vector<Elf32_Phdr> ph; for(int i=0;i<opn;i++){Elf32_Phdr p;memcpy(&p,elf.data.data()+oph+i*sizeof(p),sizeof(p));ph.push_back(p);}
        std::vector<Elf32_Shdr> sh; for(int i=0;i<osn;i++){Elf32_Shdr s;memcpy(&s,elf.data.data()+osh+i*sizeof(s),sizeof(s));sh.push_back(s);}
        std::vector<uint8_t> ss; uint32_t sso=0,ssz=0;
        if(osx<osn){sso=sh[osx].sh_offset;ssz=sh[osx].sh_size;ss.assign(elf.data.data()+sso,elf.data.data()+sso+ssz);}
        if(elf.data.size()<foff)elf.data.resize(foff,0);
        uint32_t ao=(uint32_t)elf.data.size();
        elf.data.insert(elf.data.end(),blob.begin(),blob.end());
        Elf32_Phdr np={};np.p_type=PT_LOAD;np.p_offset=ao;np.p_vaddr=va;np.p_paddr=va;
        np.p_filesz=(uint32_t)blob.size();np.p_memsz=(uint32_t)blob.size();np.p_flags=PF_R|PF_X;np.p_align=0x1000;ph.push_back(np);
        uint32_t nph=aup32((uint32_t)elf.data.size(),4);elf.data.resize(nph);
        uint32_t phsz=(uint32_t)(ph.size()*sizeof(Elf32_Phdr));
        for(auto& p:ph) if(p.p_type==PT_LOAD&&p.p_offset==ao&&p.p_vaddr==va){p.p_filesz=(nph+phsz)-ao;p.p_memsz=p.p_filesz;}
        for(auto& p:ph) if(p.p_type==PT_PHDR){p.p_offset=nph;p.p_vaddr=va+(nph-ao);p.p_paddr=p.p_vaddr;p.p_filesz=phsz;p.p_memsz=phsz;p.p_align=4;}
        for(auto&p:ph){size_t pos=elf.data.size();elf.data.resize(pos+sizeof(p));memcpy(elf.data.data()+pos,&p,sizeof(p));}
        uint32_t ni=ssz,nss=aup32((uint32_t)elf.data.size(),4);elf.data.resize(nss);
        elf.data.insert(elf.data.end(),ss.begin(),ss.end());
        for(char c:std::string(".prot"))elf.data.push_back(c);elf.data.push_back(0);
        uint32_t nssz=ssz+7;
        if(osx<(int)sh.size()){sh[osx].sh_offset=nss;sh[osx].sh_size=nssz;}
        Elf32_Shdr ns={};ns.sh_name=ni;ns.sh_type=SHT_PROGBITS;
        ns.sh_flags=(uint32_t)(SHF_ALLOC|SHF_EXECINSTR);ns.sh_addr=va;ns.sh_offset=ao;
        ns.sh_size=(uint32_t)blob.size();ns.sh_addralign=4;sh.push_back(ns);
        uint32_t nso=aup32((uint32_t)elf.data.size(),4);elf.data.resize(nso);
        for(auto&s:sh){size_t pos=elf.data.size();elf.data.resize(pos+sizeof(s));memcpy(elf.data.data()+pos,&s,sizeof(s));}
        auto*e=elf.e32();e->e_phoff=nph;e->e_phnum=(uint16_t)ph.size();e->e_shoff=nso;e->e_shnum=(uint16_t)sh.size();
    }

    void append64(ElfParser& elf,const std::vector<uint8_t>& blob,uint64_t foff,uint64_t va){
        auto*e0=elf.e64();
        uint64_t oph=e0->e_phoff,osh=e0->e_shoff;
        uint16_t opn=e0->e_phnum,osn=e0->e_shnum,osx=e0->e_shstrndx;
        std::vector<Elf64_Phdr> ph; for(int i=0;i<opn;i++){Elf64_Phdr p;memcpy(&p,elf.data.data()+oph+i*sizeof(p),sizeof(p));ph.push_back(p);}
        std::vector<Elf64_Shdr> sh; for(int i=0;i<osn;i++){Elf64_Shdr s;memcpy(&s,elf.data.data()+osh+i*sizeof(s),sizeof(s));sh.push_back(s);}
        std::vector<uint8_t> ss; uint64_t sso=0,ssz=0;
        if(osx<osn){sso=sh[osx].sh_offset;ssz=sh[osx].sh_size;ss.assign(elf.data.data()+sso,elf.data.data()+sso+ssz);}
        if((uint64_t)elf.data.size()<foff)elf.data.resize((size_t)foff,0);
        uint64_t ao=elf.data.size();
        elf.data.insert(elf.data.end(),blob.begin(),blob.end());
        Elf64_Phdr np={};np.p_type=PT_LOAD;np.p_flags=PF_R|PF_X;
        np.p_offset=ao;np.p_vaddr=va;np.p_paddr=va;np.p_filesz=blob.size();np.p_memsz=blob.size();np.p_align=0x1000;ph.push_back(np);
        uint64_t nph=aup64(elf.data.size(),8);elf.data.resize(nph);
        uint64_t phsz=ph.size()*sizeof(Elf64_Phdr);
        for(auto& p:ph) if(p.p_type==PT_LOAD&&p.p_offset==ao&&p.p_vaddr==va){p.p_filesz=(nph+phsz)-ao;p.p_memsz=p.p_filesz;}
        for(auto& p:ph) if(p.p_type==PT_PHDR){p.p_offset=nph;p.p_vaddr=va+(nph-ao);p.p_paddr=p.p_vaddr;p.p_filesz=phsz;p.p_memsz=phsz;p.p_align=8;}
        for(auto&p:ph){size_t pos=elf.data.size();elf.data.resize(pos+sizeof(p));memcpy(elf.data.data()+pos,&p,sizeof(p));}
        uint32_t ni=(uint32_t)ssz;uint64_t nss=aup64(elf.data.size(),8);elf.data.resize(nss);
        elf.data.insert(elf.data.end(),ss.begin(),ss.end());
        for(char c:std::string(".prot"))elf.data.push_back(c);elf.data.push_back(0);
        uint64_t nssz=ssz+7;
        if(osx<(int)sh.size()){sh[osx].sh_offset=nss;sh[osx].sh_size=nssz;}
        Elf64_Shdr ns={};ns.sh_name=ni;ns.sh_type=SHT_PROGBITS;
        ns.sh_flags=SHF_ALLOC|SHF_EXECINSTR;ns.sh_addr=va;ns.sh_offset=ao;
        ns.sh_size=blob.size();ns.sh_addralign=8;sh.push_back(ns);
        uint64_t nso=aup64(elf.data.size(),8);elf.data.resize(nso);
        for(auto&s:sh){size_t pos=elf.data.size();elf.data.resize(pos+sizeof(s));memcpy(elf.data.data()+pos,&s,sizeof(s));}
        auto*e=elf.e64();e->e_phoff=nph;e->e_phnum=(uint16_t)ph.size();e->e_shoff=nso;e->e_shnum=(uint16_t)sh.size();
    }
};
