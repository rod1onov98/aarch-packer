#pragma once
#include "elf_parser.h"
#include "arch_arm32.h"
#include "arch_arm64.h"
#include "crypto.h"
#include "integrity.h"
#include "string_enc.h"
#include "sec_renamer.h"
#include "config.h"
#include <vector>
#include <unordered_map>
#include <cstdio>
#include <cstring>
#include <algorithm>

static inline uint64_t aup64(uint64_t v,uint64_t a){return(v+a-1)&~(a-1);}
static inline uint32_t aup32(uint32_t v,uint32_t a){return(v+a-1)&~(a-1);}

static const uint32_t PROT_MAGIC_RAW = 0x544F5250u;
static const uint32_t PROT_MAGIC_MASK = 0xC01EBA42u;
static const uint32_t WLIST_MAGIC = 0x54534C57u; // "WLST"
static inline uint32_t obf_magic(uint32_t m){return m^PROT_MAGIC_MASK;}

static inline std::vector<uint8_t> build_whitelist_blob(const std::vector<std::string>& libs){
    if(libs.empty()) return {};
    std::vector<uint32_t> hashes;
    for(auto&lib:libs) hashes.push_back(xxhash32((const uint8_t*)lib.c_str(),(uint32_t)lib.size()));
    uint32_t sz=8+(uint32_t)(hashes.size()*4);
    std::vector<uint8_t> blob(sz,0);
    uint32_t mag=WLIST_MAGIC,n=(uint32_t)hashes.size();
    memcpy(blob.data(),&mag,4);
    memcpy(blob.data()+4,&n,4);
    for(size_t i=0;i<hashes.size();i++)
        memcpy(blob.data()+8+i*4,&hashes[i],4);
    return blob;
}

class Protector {
public:
    bool verbose = false;
    ProtConfig cfg;

    void run(const std::string& in, const std::string& out) {
        ElfParser elf;
        printf("[*] Loading %s\n", in.c_str());
        elf.load(in);
        printf("[*] Arch: %s\n", elf.arch==Arch::ARM64?"ARM64":"ARM32");
        cfg.print();
        if (elf.arch==Arch::ARM64) run64(elf);
        else run32(elf);
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

    void encrypt_with_skips(ElfParser& elf, uint32_t sec_off, uint32_t sec_size, const std::vector<SkipRange>& skips, uint64_t sec_va) {
        uint32_t cur=sec_off, end=sec_off+sec_size;
        for(auto&sk:skips){
            if(cur<sk.off) crypt_block_region(elf.data.data()+cur,sk.off-cur,sec_va+(cur-sec_off));
            cur=sk.off+sk.size;
        }
        if(cur<end) crypt_block_region(elf.data.data()+cur,end-cur,sec_va+(cur-sec_off));
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

        // exclude the decryptors own section from call-site rewriting (see run64).
        uint32_t prot_text_lo=0, prot_text_hi=0;
        {
            auto*eh=elf.e32();
            Elf32_Shdr strsh; memcpy(&strsh,elf.data.data()+eh->e_shoff+eh->e_shstrndx*sizeof(strsh),sizeof(strsh));
            for(int i=0;i<eh->e_shnum;i++){
                Elf32_Shdr sh; memcpy(&sh,elf.data.data()+eh->e_shoff+i*sizeof(sh),sizeof(sh));
                const char* sn=(const char*)elf.data.data()+strsh.sh_offset+sh.sh_name;
                if(strcmp(sn,".prot_text")==0){prot_text_lo=sh.sh_addr;prot_text_hi=sh.sh_addr+sh.sh_size;break;}
            }
        }
        auto in_prot_text=[&](uint64_t va){uint64_t v=va&~1ull;return prot_text_lo&&v>=prot_text_lo&&v<prot_text_hi;};

        std::vector<CallSite> calls;
        for(auto&fi:funcs){
            if(!fi.size||fi.offset+fi.size>elf.data.size()) continue;
            if(in_prot_text(fi.va)) continue;
            auto s=fi.is_thumb?scan_thumb(elf.data.data()+fi.offset,(uint32_t)fi.offset,(uint32_t)fi.va,(uint32_t)fi.size):scan_arm32(elf.data.data()+fi.offset,(uint32_t)fi.offset,(uint32_t)fi.va,(uint32_t)fi.size);
            for(auto&cs:s) if(is_int(cs.target_va)&&!in_prot_text(cs.target_va)) calls.push_back(cs);
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
            for(auto&es:esecs)
                ihashes.push_back({es.addr,0}); // hash finalized after mutation, before encryption
        }

        uint64_t new_va=aup64(elf.max_va(),0x1000);
        uint64_t new_foff=aup64(elf.data.size(),0x1000);
        size_t N=calls.size();

        struct Reg32{uint32_t va_off,size;};
        std::vector<Reg32> enc_regs;
        for(auto&es:esecs) enc_regs.push_back({es.addr,es.size});
        struct CritReg32{uint32_t va,size;};
        std::vector<CritReg32> crit_regs;

        uint32_t hdr_sz =8+(uint32_t)(enc_regs.size()*8);
        uint32_t table_off=hdr_sz;
        uint32_t stubs_off=table_off+(uint32_t)(N*8);
        uint32_t integ_off=aup32(stubs_off+(uint32_t)(N*A32_STUB_SIZE),4);
        uint32_t integ_sz =8+(uint32_t)(ihashes.size()*8);
        uint32_t prot_sz =aup32(integ_off+integ_sz,4);

        std::vector<uint8_t> blob(prot_sz,0);
        uint32_t magic=cfg.obfuscate_magic?obf_magic(PROT_MAGIC_RAW):PROT_MAGIC_RAW;
        uint32_t nreg=(uint32_t)enc_regs.size();
        memcpy(blob.data(),&magic,4);
        memcpy(blob.data()+4,&nreg,4);
        for(size_t ri=0;ri<enc_regs.size();ri++){
            memcpy(blob.data()+8+ri*8,&enc_regs[ri].va_off,4);
            memcpy(blob.data()+8+ri*8+4,&enc_regs[ri].size,4);
        }

        std::vector<uint32_t> stub_vas(N);
        for(size_t i=0;i<N;i++){
            uint32_t sv=(uint32_t)(new_va+stubs_off+i*A32_STUB_SIZE);
            uint32_t ev=(uint32_t)(new_va+table_off+4*i);
            stub_vas[i]=sv;
            uint32_t enc=encode_offset((int32_t)(sv-ev));
            memcpy(blob.data()+table_off+4*i,&enc,4);
            uint32_t tgt=(uint32_t)calls[i].target_va|(calls[i].target_thumb?1u:0u);
            memcpy(blob.data()+table_off+N*4+4*i,&tgt,4);
            write_arm32_stub_pcrel(blob.data()+stubs_off+i*A32_STUB_SIZE,sv,(uint32_t)calls[i].target_va,calls[i].target_thumb);
        }

        uint32_t imag=INTEGRITY_MAGIC,nh=(uint32_t)ihashes.size();
        memcpy(blob.data()+integ_off,&imag,4);
        memcpy(blob.data()+integ_off+4,&nh,4);
        for(size_t i=0;i<ihashes.size();i++){
            memcpy(blob.data()+integ_off+8+i*8,&ihashes[i].va_off,4);
            memcpy(blob.data()+integ_off+8+i*8+4,&ihashes[i].hash,4);
        }

        std::vector<uint8_t> str_blob;
        if(cfg.encrypt_text){
            printf("[*] Encrypting strings...\n");
            str_blob=encrypt_strings(elf.data,false);
        }

        printf("[*] Patching %zu call sites...\n",N);
        for(size_t i=0;i<N;i++)
            patch_arm32_callsite(elf.data.data(),calls[i],stub_vas[i]);

        if(cfg.encrypt_text){
            printf("[*] Finalizing integrity hashes (post-mutation)...\n");
            for(size_t i=0;i<esecs.size()&&i<ihashes.size();i++){
                uint32_t h=xxhash32(elf.data.data()+esecs[i].off,esecs[i].size);
                ihashes[i].hash=h;
                memcpy(blob.data()+integ_off+8+i*8,&ihashes[i].va_off,4);
                memcpy(blob.data()+integ_off+8+i*8+4,&h,4);
                printf("[*]   VA=0x%x: 0x%08x\n",esecs[i].addr,h);
            }
            printf("[*] Encrypting sections...\n");
            for(auto&es:esecs){
                printf("[*]   off=0x%x size=0x%x\n",es.off,es.size);
                auto skips=get_skips(elf,es.off,es.size);
                for(auto&sk:skips)
                    printf("[*]   Skip off=0x%x size=%u\n",sk.off,sk.size);
                encrypt_with_skips(elf,es.off,es.size,skips,(uint64_t)es.addr);
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
                crypt_critical(elf.data.data()+foff,sz,cf.va);
                crit_regs.push_back({(uint32_t)cf.va,sz});
                printf("[*]   crit %s @ 0x%llx size=%u\n", cf.name.c_str(),(unsigned long long)cf.va,sz);
            }
        }

        if(!crit_regs.empty()){
            uint32_t pad=aup32((uint32_t)blob.size(),4)-(uint32_t)blob.size();
            blob.resize(blob.size()+pad,0);
            uint32_t cmag=CRIT_MAGIC,nc=(uint32_t)crit_regs.size();
            size_t base=blob.size();
            blob.resize(base+8+crit_regs.size()*8,0);
            memcpy(blob.data()+base,&cmag,4);
            memcpy(blob.data()+base+4,&nc,4);
            for(size_t i=0;i<crit_regs.size();i++){
                memcpy(blob.data()+base+8+i*8,&crit_regs[i].va,4);
                memcpy(blob.data()+base+8+i*8+4,&crit_regs[i].size,4);
            }
            printf("[*] Critical table: %zu regions\n",crit_regs.size());
        }

        if(!str_blob.empty()){
            uint32_t pad=aup32((uint32_t)blob.size(),4)-(uint32_t)blob.size();
            blob.resize(blob.size()+pad,0);
            blob.insert(blob.end(),str_blob.begin(),str_blob.end());
            printf("[*] String table: %zu bytes\n",str_blob.size());
        }

        {
            auto wl_blob=build_whitelist_blob(cfg.whitelist_libs);
            if(!wl_blob.empty()){
                uint32_t pad=aup32((uint32_t)blob.size(),4)-(uint32_t)blob.size();
                blob.resize(blob.size()+pad,0);
                blob.insert(blob.end(),wl_blob.begin(),wl_blob.end());
                printf("[*] Whitelist: %zu entries, %zu bytes\n",cfg.whitelist_libs.size(),wl_blob.size());
            }
        }

        append32(elf,blob,(uint32_t)new_foff,(uint32_t)new_va);

        patch_init_array32(elf);
        strip_prot_symbols(elf,false);

        elf.snapshot_headers();
        if(cfg.rename_sections){
            printf("[*] Renaming sections...\n");
            SecRenamer sr; sr.skip_init_array=cfg.skip_init_array;
            sr.run(elf.data,false,cfg.name_seed);
        }
        mask_prot_sections(elf,false);
        elf.snapshot_headers();
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

        // .prot_text holds the decryptor (_prot_init, do_decrypt, dreg, cc20x...).
        // its internal BL calls must not be rewritten into stubs: the stubs live in
        // the .prot segment (last LOAD) and the decryptor runs at the very start of
        // load, before relying on anything external. patching them would route early
        // init through code that may not be in place yet. skip both calls FROM and
        // calls landing inside .prot_text.
        uint64_t prot_text_lo=0, prot_text_hi=0;
        {
            auto*eh=elf.e64();
            Elf64_Shdr strsh; memcpy(&strsh,elf.data.data()+eh->e_shoff+eh->e_shstrndx*sizeof(strsh),sizeof(strsh));
            for(int i=0;i<eh->e_shnum;i++){
                Elf64_Shdr sh; memcpy(&sh,elf.data.data()+eh->e_shoff+i*sizeof(sh),sizeof(sh));
                const char* sn=(const char*)elf.data.data()+strsh.sh_offset+sh.sh_name;
                if(strcmp(sn,".prot_text")==0){prot_text_lo=sh.sh_addr;prot_text_hi=sh.sh_addr+sh.sh_size;break;}
            }
        }
        auto in_prot_text=[&](uint64_t va){return prot_text_lo&&va>=prot_text_lo&&va<prot_text_hi;};

        std::vector<CallSite64> calls;
        for(auto&fi:funcs){
            if(!fi.size||fi.offset+fi.size>elf.data.size()) continue;
            if(in_prot_text(fi.va)) continue; // don't scan decryptor functions
            auto s=scan_arm64(elf.data.data()+fi.offset,fi.offset,fi.va,fi.size);
            for(auto&cs:s) if(is_int(cs.target_va)&&!in_prot_text(cs.target_va)) calls.push_back(cs);
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
            for(auto&es:esecs)
                ihashes.push_back({es.addr,0,0}); // hash finalized after mutation, before encryption

        uint64_t new_va  =aup64(elf.max_va(),0x1000);
        uint64_t new_foff=aup64(elf.data.size(),0x1000);
        size_t   N=calls.size();

        struct Reg64{uint64_t va_off,size;};
        std::vector<Reg64> enc_regs;
        for(auto&es:esecs) enc_regs.push_back({es.addr,es.size});
        struct CritReg64{uint64_t va,size;};
        std::vector<CritReg64> crit_regs;

        uint64_t hdr_sz=8+enc_regs.size()*16;
        uint64_t table_off=hdr_sz;
        uint64_t stubs_off=table_off+N*16;
        uint64_t integ_off=aup64(stubs_off+N*A64_STUB_SIZE,8);
        uint64_t integ_sz=8+ihashes.size()*16;
        uint64_t prot_sz=aup64(integ_off+integ_sz,8);

        std::vector<uint8_t> blob((size_t)prot_sz,0);
        uint32_t magic=cfg.obfuscate_magic?obf_magic(PROT_MAGIC_RAW):PROT_MAGIC_RAW;
        uint32_t nreg=(uint32_t)enc_regs.size();
        memcpy(blob.data(),&magic,4);
        memcpy(blob.data()+4,&nreg,4);
        for(size_t ri=0;ri<enc_regs.size();ri++){
            memcpy(blob.data()+8+ri*16,&enc_regs[ri].va_off,8);
            memcpy(blob.data()+8+ri*16+8,&enc_regs[ri].size,8);
        }
        std::vector<uint64_t> stub_vas(N);
        for(size_t i=0;i<N;i++){
            uint64_t sv=new_va+stubs_off+i*A64_STUB_SIZE;
            stub_vas[i]=sv;
            uint32_t lo=encode_offset((int32_t)((sv-(new_va+table_off+8*i))&0xFFFFFFFF));
            uint32_t hi=encode_offset((int32_t)((sv-(new_va+table_off+8*i))>>32));
            memcpy(blob.data()+table_off+8*i,&lo,4);
            memcpy(blob.data()+table_off+8*i+4,&hi,4);
            uint64_t tgt=calls[i].target_va;
            memcpy(blob.data()+table_off+N*8+8*i,&tgt,8);
            write_a64_stub_pcrel(blob.data()+(size_t)stubs_off+i*A64_STUB_SIZE,sv,tgt);
        }
        uint32_t imag=INTEGRITY_MAGIC,nh=(uint32_t)ihashes.size();
        memcpy(blob.data()+integ_off,&imag,4);
        memcpy(blob.data()+integ_off+4,&nh,4);
        for(size_t i=0;i<ihashes.size();i++){
            memcpy(blob.data()+integ_off+8+i*16,&ihashes[i].va_off,8);
            memcpy(blob.data()+integ_off+8+i*16+8,&ihashes[i].hash,4);
        }

        std::vector<uint8_t> str_blob;
        if(cfg.encrypt_text){
            printf("[*] Encrypting strings...\n");
            str_blob=encrypt_strings(elf.data,true);
        }

        printf("[*] Patching %zu call sites...\n",N);
        for(size_t i=0;i<N;i++)
            patch_a64_callsite(elf.data.data(),calls[i],stub_vas[i]);

        if(cfg.encrypt_text){
            printf("[*] Finalizing integrity hashes (post-mutation)...\n");
            for(size_t i=0;i<esecs.size()&&i<ihashes.size();i++){
                uint32_t h=xxhash32(elf.data.data()+(size_t)esecs[i].off,(size_t)esecs[i].size);
                ihashes[i].hash=h;
                memcpy(blob.data()+integ_off+8+i*16,&ihashes[i].va_off,8);
                memcpy(blob.data()+integ_off+8+i*16+8,&h,4);
                printf("[*]   VA=0x%lx: 0x%08x\n",(unsigned long)esecs[i].addr,h);
            }
            printf("[*] Encrypting sections...\n");
            for(auto&es:esecs){
                printf("[*]   off=0x%lx size=0x%lx\n",(unsigned long)es.off,(unsigned long)es.size);
                auto skips=get_skips(elf,(uint32_t)es.off,(uint32_t)es.size);
                for(auto&sk:skips)
                    printf("[*]   Skip off=0x%x size=%u\n",sk.off,sk.size);
                encrypt_with_skips(elf,(uint32_t)es.off,(uint32_t)es.size,skips,es.addr);
            }
        }

        if(!cfg.critical_funcs.empty())
            for(auto&cf:cfg.critical_funcs){
                uint32_t sz=cf.size;
                if(!sz) for(auto&fi:funcs) if(fi.va==cf.va){sz=(uint32_t)fi.size;break;}
                if(!sz) continue;
                uint64_t foff=0;
                try{foff=elf.va_to_offset(cf.va);}catch(...){continue;}
                crypt_critical(elf.data.data()+foff,sz,cf.va);
                crit_regs.push_back({cf.va,sz});
                printf("[*]   crit %s @ 0x%llx size=%u\n", cf.name.c_str(),(unsigned long long)cf.va,sz);
            }

        if(!crit_regs.empty()){
            uint64_t pad=aup64((uint64_t)blob.size(),8)-(uint64_t)blob.size();
            blob.resize(blob.size()+pad,0);
            uint32_t cmag=CRIT_MAGIC,nc=(uint32_t)crit_regs.size();
            size_t base=blob.size();
            blob.resize(base+8+crit_regs.size()*16,0);
            memcpy(blob.data()+base,&cmag,4);
            memcpy(blob.data()+base+4,&nc,4);
            for(size_t i=0;i<crit_regs.size();i++){
                memcpy(blob.data()+base+8+i*16,&crit_regs[i].va,8);
                memcpy(blob.data()+base+8+i*16+8,&crit_regs[i].size,8);
            }
            printf("[*] Critical table: %zu regions\n",crit_regs.size());
        }

        if(!str_blob.empty()){
            uint64_t pad=aup64((uint64_t)blob.size(),8)-(uint64_t)blob.size();
            blob.resize(blob.size()+pad,0);
            blob.insert(blob.end(),str_blob.begin(),str_blob.end());
            printf("[*] String table: %zu bytes\n",str_blob.size());
        }

        {
            auto wl_blob=build_whitelist_blob(cfg.whitelist_libs);
            if(!wl_blob.empty()){
                uint64_t pad=aup64((uint64_t)blob.size(),8)-(uint64_t)blob.size();
                blob.resize(blob.size()+pad,0);
                blob.insert(blob.end(),wl_blob.begin(),wl_blob.end());
                printf("[*] Whitelist: %zu entries, %zu bytes\n",cfg.whitelist_libs.size(),wl_blob.size());
            }
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
                // PIE libraries relocate every .init_array slot at load time, so
                // patching the slot's file value is useless — the dynamic linker
                // overwrites it from .rela.dyn (R_AARCH64_RELATIVE: slot = base+addend,
                // or ABS64: slot = base+sym). We must reorder the RELOCATIONS so
                // _prot_init runs FIRST, with the original constructors after it.
                //
                // layout produced by the compiler (constructor attribute):
                //   slots = [ ctor0, ctor1, ..., _prot_init ]  (prot_init usually last)
                // target layout:
                //   slots = [ _prot_init, ctor0, ctor1, ... ]
                Elf64_Shdr iash{}; bool have_ia=false; uint64_t ia_addr=0,ia_size=0;
                for(int si=0;si<eh2->e_shnum;si++){
                    Elf64_Shdr sh; memcpy(&sh,elf.data.data()+eh2->e_shoff+si*sizeof(sh),sizeof(sh));
                    if(sh.sh_type==14){iash=sh;have_ia=true;ia_addr=sh.sh_addr;ia_size=sh.sh_size;break;}
                }
                if(!have_ia){printf("[!] no .init_array\n");}
                else{
                    uint64_t nslot=ia_size/8;
                    // collect relocations whose r_offset lands in the init_array range
                    struct R{uint64_t sec_off;uint64_t slot;uint64_t info;int64_t addend;};
                    std::vector<R> rels;
                    int rela_idx=-1; Elf64_Shdr relash{};
                    for(int si=0;si<eh2->e_shnum;si++){
                        Elf64_Shdr sh; memcpy(&sh,elf.data.data()+eh2->e_shoff+si*sizeof(sh),sizeof(sh));
                        if(sh.sh_type!=4||!sh.sh_entsize) continue; // RELA
                        for(uint64_t k=0;k<sh.sh_size/sh.sh_entsize;k++){
                            uint64_t ro; memcpy(&ro,elf.data.data()+sh.sh_offset+k*sh.sh_entsize,8);
                            if(ro>=ia_addr&&ro<ia_addr+ia_size){
                                R r; r.sec_off=sh.sh_offset+k*sh.sh_entsize; r.slot=(ro-ia_addr)/8;
                                memcpy(&r.info,elf.data.data()+r.sec_off+8,8);
                                memcpy(&r.addend,elf.data.data()+r.sec_off+16,8);
                                rels.push_back(r);
                                rela_idx=si; relash=sh;
                            }
                        }
                    }
                    const uint64_t R_AARCH64_RELATIVE=1027; // 0x403
                    if(rels.empty()){
                        printf("[!] no relocations cover .init_array — writing raw slot (non-PIE?)\n");
                        for(uint64_t j=0;j<nslot;j++){
                            uint64_t val; memcpy(&val,elf.data.data()+iash.sh_offset+j*8,8);
                            if(val==0){memcpy(elf.data.data()+iash.sh_offset+j*8,&prot_init_va,8);
                                printf("[*] Patched .init_array[%llu]=0x%llx\n",(unsigned long long)j,(unsigned long long)prot_init_va);break;}
                        }
                    }else{
                        // gather original target VAs in slot order
                        std::sort(rels.begin(),rels.end(),[](const R&a,const R&b){return a.slot<b.slot;});
                        const uint32_t RT_ABS64=257; // 0x101
                        std::vector<int64_t> orig;
                        for(auto&r:rels){
                            uint32_t rtype=(uint32_t)(r.info&0xffffffff);
                            uint32_t rsym =(uint32_t)(r.info>>32);
                            if(rtype==RT_ABS64 && rsym){
                                // resolve symbol value from .dynsym (sh_link of this RELA's section)
                                uint64_t symval=0;
                                Elf64_Shdr dynsymsh; bool okds=false;
                                if(relash.sh_link<eh2->e_shnum){
                                    memcpy(&dynsymsh,elf.data.data()+eh2->e_shoff+relash.sh_link*sizeof(dynsymsh),sizeof(dynsymsh));
                                    if(dynsymsh.sh_entsize){
                                        Elf64_Sym s; memcpy(&s,elf.data.data()+dynsymsh.sh_offset+rsym*dynsymsh.sh_entsize,sizeof(s));
                                        symval=s.st_value; okds=true;
                                    }
                                }
                                orig.push_back((int64_t)(symval+(uint64_t)r.addend));
                                if(!okds) printf("[!] ABS64 reloc: could not resolve sym %u\n",rsym);
                            } else {
                                orig.push_back(r.addend); // RELATIVE: target = base+addend
                            }
                        }
                        // build desired order: _prot_init first, then the others EXCEPT
                        // the one that already pointed at _prot_init (drop the dup).
                        std::vector<int64_t> desired;
                        desired.push_back((int64_t)prot_init_va);
                        for(size_t i=0;i<orig.size();i++){
                            if((uint64_t)orig[i]==prot_init_va) continue; // skip prot_init's own slot
                            desired.push_back(orig[i]);
                        }
                        // pad to slot count (shouldn't trigger, but stay safe)
                        while(desired.size()<rels.size()) desired.push_back((int64_t)prot_init_va);
                        // rewrite every covering reloc as RELATIVE with the desired addend,
                        // in ascending slot order
                        uint64_t relmask_hi = 0; // sym index 0 for RELATIVE
                        for(size_t i=0;i<rels.size();i++){
                            uint64_t newinfo=(relmask_hi<<32)|R_AARCH64_RELATIVE;
                            int64_t  newadd =desired[i];
                            uint8_t* base=elf.data.data()+rels[i].sec_off;
                            memcpy(base+8,&newinfo,8);
                            memcpy(base+16,&newadd,8);
                            // also clear the file slot value (linker overwrites anyway)
                            uint64_t zero=0; memcpy(elf.data.data()+iash.sh_offset+rels[i].slot*8,&zero,8);
                            printf("[*] init reloc slot[%llu] -> RELATIVE addend=0x%llx%s\n", (unsigned long long)rels[i].slot,(unsigned long long)(uint64_t)newadd, i==0?"  (_prot_init, runs first)":"");
                        }
                    }
                }
            } else {
                printf("[!] _prot_init not found in symtab\n");
            }
        }

        strip_prot_symbols(elf,true);

        elf.snapshot_headers();
        if(cfg.rename_sections){SecRenamer sr;sr.skip_init_array=cfg.skip_init_array;sr.run(elf.data,true,cfg.name_seed);}
        mask_prot_sections(elf,true);
        elf.snapshot_headers();
    }

    // hide the decryptor's symbol names from the disassembler.
    // we touch ONLY .symtab (type 2): the loader ignores it, but nm/IDA read it
    // first and it carries the "talking" names. We deliberately DO NOT touch
    // .dynsym (type 11): renaming there desyncs .hash/.gnu.hash chains (lookups
    // hash the new name, miss the chain -> "cannot locate symbol"), and zeroing
    // the name yields "cannot locate symbol \"\"". Removing them from dynsym
    // properly needs a hash-table rebuild — deferred to the stage-0 step.
    void strip_prot_symbols(ElfParser& elf, bool is64){
        static const char* names[] = {"_prot_init","_prot_begin","_prot_init_end"};
        if(!is64){
            auto*eh=elf.e32();
            for(int si=0;si<eh->e_shnum;si++){
                Elf32_Shdr sh; memcpy(&sh,elf.data.data()+eh->e_shoff+si*sizeof(sh),sizeof(sh));
                if(sh.sh_type!=2||!sh.sh_entsize) continue; // SYMTAB only
                Elf32_Shdr strsh; memcpy(&strsh,elf.data.data()+eh->e_shoff+sh.sh_link*sizeof(strsh),sizeof(strsh));
                for(uint32_t j=0;j<sh.sh_size/sh.sh_entsize;j++){
                    size_t soff=sh.sh_offset+j*sh.sh_entsize;
                    Elf32_Sym sym; memcpy(&sym,elf.data.data()+soff,sizeof(sym));
                    if(!sym.st_name) continue;
                    char* p=(char*)elf.data.data()+strsh.sh_offset+sym.st_name;
                    for(auto*want:names) if(!strcmp(p,want)){
                        size_t len=strlen(p);
                        for(size_t k=0;k<len;k++)p[k]=0;
                        sym.st_name=0; memcpy(elf.data.data()+soff,&sym,sizeof(sym));
                        printf("[*] stripped symbol '%s' (symtab)\n",want);
                        break;
                    }
                }
            }
        } else {
            auto*eh=elf.e64();
            for(int si=0;si<eh->e_shnum;si++){
                Elf64_Shdr sh; memcpy(&sh,elf.data.data()+eh->e_shoff+si*sizeof(sh),sizeof(sh));
                if(sh.sh_type!=2||!sh.sh_entsize) continue; // SYMTAB only
                Elf64_Shdr strsh; memcpy(&strsh,elf.data.data()+eh->e_shoff+sh.sh_link*sizeof(strsh),sizeof(strsh));
                for(uint64_t j=0;j<sh.sh_size/sh.sh_entsize;j++){
                    size_t soff=sh.sh_offset+j*sh.sh_entsize;
                    Elf64_Sym sym; memcpy(&sym,elf.data.data()+soff,sizeof(sym));
                    if(!sym.st_name) continue;
                    char* p=(char*)elf.data.data()+strsh.sh_offset+sym.st_name;
                    for(auto*want:names) if(!strcmp(p,want)){
                        size_t len=strlen(p);
                        for(size_t k=0;k<len;k++)p[k]=0;
                        sym.st_name=0; memcpy(elf.data.data()+soff,&sym,sizeof(sym));
                        printf("[*] stripped symbol '%s' (symtab)\n",want);
                        break;
                    }
                }
            }
        }
    }

    // rename the protector's own sections (.prot_text/.prot_data/.prot) to
    // neutral names so they are not obvious markers, even when the global
    // rename_sections option is off. Renames in place within shstrtab (new
    // names are <= old length).
    void mask_prot_sections(ElfParser& elf, bool is64){
        const char* repl[][2] = {
            {".prot_text",".text.0"}, {".prot_data",".rodata0"}, {".prot",".note0"}
        };
        auto do_one=[&](uint64_t shoff,uint64_t shentsize,uint16_t shnum,uint64_t shstr_off){
            for(int i=0;i<(int)shnum;i++){
                uint32_t nameoff;
                memcpy(&nameoff, elf.data.data()+shoff+i*shentsize, 4); // sh_name is first field
                char* nm=(char*)elf.data.data()+shstr_off+nameoff;
                for(auto& r:repl){
                    if(!strcmp(nm,r[0])){
                        size_t ol=strlen(r[0]), nl=strlen(r[1]);
                        if(nl<=ol){ memset(nm,0,ol); memcpy(nm,r[1],nl); printf("[*] masked section %s -> %s\n",r[0],r[1]); }
                        break;
                    }
                }
            }
        };
        if(!is64){
            auto*eh=elf.e32();
            Elf32_Shdr ss; memcpy(&ss,elf.data.data()+eh->e_shoff+eh->e_shstrndx*sizeof(ss),sizeof(ss));
            do_one(eh->e_shoff,sizeof(Elf32_Shdr),eh->e_shnum,ss.sh_offset);
        } else {
            auto*eh=elf.e64();
            Elf64_Shdr ss; memcpy(&ss,elf.data.data()+eh->e_shoff+eh->e_shstrndx*sizeof(ss),sizeof(ss));
            do_one(eh->e_shoff,sizeof(Elf64_Shdr),eh->e_shnum,ss.sh_offset);
        }
    }

    void patch_init_array32(ElfParser& elf){
        auto*eh2=elf.e32();
        // 1) find _prot_init VA (keep Thumb LSB from the symbol value)
        uint32_t prot_init_va=0; bool prot_thumb=false;
        for(int si=0;si<eh2->e_shnum&&!prot_init_va;si++){
            Elf32_Shdr sh; memcpy(&sh,elf.data.data()+eh2->e_shoff+si*sizeof(sh),sizeof(sh));
            if((sh.sh_type!=2&&sh.sh_type!=11)||!sh.sh_entsize) continue;
            Elf32_Shdr strsh; memcpy(&strsh,elf.data.data()+eh2->e_shoff+sh.sh_link*sizeof(strsh),sizeof(strsh));
            for(uint32_t j=0;j<sh.sh_size/sh.sh_entsize;j++){
                Elf32_Sym sym; memcpy(&sym,elf.data.data()+sh.sh_offset+j*sh.sh_entsize,sizeof(sym));
                if(!sym.st_value) continue;
                const char* nm=(const char*)elf.data.data()+strsh.sh_offset+sym.st_name;
                if(strcmp(nm,"_prot_init")==0){prot_init_va=sym.st_value&~1u;prot_thumb=(sym.st_value&1)||(ELF32_ST_TYPE(sym.st_info)==STT_FUNC);break;}
            }
        }
        if(!prot_init_va){
            for(int si=0;si<eh2->e_shnum;si++){
                Elf32_Shdr sh; memcpy(&sh,elf.data.data()+eh2->e_shoff+si*sizeof(sh),sizeof(sh));
                Elf32_Shdr strsh2; memcpy(&strsh2,elf.data.data()+eh2->e_shoff+eh2->e_shstrndx*sizeof(strsh2),sizeof(strsh2));
                const char* sn=(const char*)elf.data.data()+strsh2.sh_offset+sh.sh_name;
                if(strcmp(sn,".prot_text")==0){prot_init_va=sh.sh_addr;prot_thumb=true;break;}
            }
            if(prot_init_va) printf("[*] _prot_init VA inferred from .prot_text: 0x%x (thumb)\n",prot_init_va);
        }

        // 2) reorder .init_array so _prot_init runs first (PIE: REL R_ARM_RELATIVE,
        //    addend stored in-place in the slot; the slot LSB is the Thumb bit).
        Elf32_Shdr iash{}; bool have_ia=false;
        for(int i=0;i<eh2->e_shnum;i++){
            Elf32_Shdr sh; memcpy(&sh,elf.data.data()+eh2->e_shoff+i*sizeof(sh),sizeof(sh));
            if(sh.sh_type==14){iash=sh;have_ia=true;break;}
        }
        const uint32_t R_ARM_RELATIVE=23, R_ARM_ABS32=2;
        if(prot_init_va&&have_ia){
            uint32_t ia_addr=iash.sh_addr, ia_size=iash.sh_size;
            struct R{uint32_t sec_off;uint32_t slot;uint32_t info;};
            std::vector<R> rels; Elf32_Shdr relsh{};
            for(int si=0;si<eh2->e_shnum;si++){
                Elf32_Shdr sh; memcpy(&sh,elf.data.data()+eh2->e_shoff+si*sizeof(sh),sizeof(sh));
                if((sh.sh_type!=9&&sh.sh_type!=4)||!sh.sh_entsize) continue; // REL or RELA
                uint32_t ent=sh.sh_entsize;
                for(uint32_t k=0;k<sh.sh_size/ent;k++){
                    uint32_t ro; memcpy(&ro,elf.data.data()+sh.sh_offset+k*ent,4);
                    if(ro>=ia_addr&&ro<ia_addr+ia_size){
                        R r; r.sec_off=sh.sh_offset+k*ent; r.slot=(ro-ia_addr)/4;
                        memcpy(&r.info,elf.data.data()+r.sec_off+4,4);
                        rels.push_back(r); relsh=sh;
                    }
                }
            }
            uint32_t pv=prot_init_va|(prot_thumb?1u:0u);
            if(rels.empty()){
                // non-PIE or no dynamic relocs: write into first empty slot directly
                for(uint32_t j=0;j<ia_size/4;j++){
                    uint32_t val; memcpy(&val,elf.data.data()+iash.sh_offset+j*4,4);
                    if(val==0){memcpy(elf.data.data()+iash.sh_offset+j*4,&pv,4);
                        printf("[*] Patched .init_array[%u]=0x%x (_prot_init)\n",j,pv);break;}
                }
            }else{
                std::sort(rels.begin(),rels.end(),[](const R&a,const R&b){return a.slot<b.slot;});
                std::vector<uint32_t> orig;
                for(auto&r:rels){
                    uint32_t rtype=r.info&0xff, rsym=r.info>>8;
                    uint32_t inplace; memcpy(&inplace,elf.data.data()+iash.sh_offset+r.slot*4,4);
                    if(rtype==R_ARM_ABS32&&rsym){
                        uint32_t symval=0;
                        if(relsh.sh_link<eh2->e_shnum){
                            Elf32_Shdr dss; memcpy(&dss,elf.data.data()+eh2->e_shoff+relsh.sh_link*sizeof(dss),sizeof(dss));
                            if(dss.sh_entsize){Elf32_Sym s; memcpy(&s,elf.data.data()+dss.sh_offset+rsym*dss.sh_entsize,sizeof(s)); symval=s.st_value;}
                        }
                        orig.push_back(symval+inplace);
                    }else{
                        orig.push_back(inplace); // R_ARM_RELATIVE: target = in-place addend
                    }
                }
                std::vector<uint32_t> desired; desired.push_back(pv);
                for(size_t i=0;i<orig.size();i++){ if((orig[i]&~1u)==prot_init_va) continue; desired.push_back(orig[i]); }
                while(desired.size()<rels.size()) desired.push_back(pv);
                for(size_t i=0;i<rels.size();i++){
                    uint32_t newinfo=(0u<<8)|R_ARM_RELATIVE; // sym 0
                    memcpy(elf.data.data()+rels[i].sec_off+4,&newinfo,4);
                    memcpy(elf.data.data()+iash.sh_offset+rels[i].slot*4,&desired[i],4);
                    printf("[*] init reloc slot[%u] -> R_ARM_RELATIVE val=0x%x%s\n", rels[i].slot,desired[i],i==0?"  (_prot_init, runs first)":"");
                }
            }
        }else if(!prot_init_va){
            printf("[!] _prot_init not found (arm32)\n");
        }
    }

    // recoded my old unreadable stuff :)
    void append32(ElfParser& elf, const std::vector<uint8_t>& blob, uint32_t foff, uint32_t va)
    {
        Elf32_Ehdr* ehdr = elf.e32();
        uint32_t ph_off = ehdr->e_phoff;
        uint32_t sh_off = ehdr->e_shoff;
        uint16_t ph_cnt = ehdr->e_phnum;
        uint16_t sh_cnt = ehdr->e_shnum;
        uint16_t shstr = ehdr->e_shstrndx;

        std::vector<Elf32_Phdr> phdrs(ph_cnt);
        for (uint16_t i = 0; i < ph_cnt; ++i)
            memcpy(&phdrs[i], elf.data.data() + ph_off + i * sizeof(Elf32_Phdr), sizeof(Elf32_Phdr));

        std::vector<Elf32_Shdr> shdrs(sh_cnt);
        for (uint16_t i = 0; i < sh_cnt; ++i)
            memcpy(&shdrs[i], elf.data.data() + sh_off + i * sizeof(Elf32_Shdr), sizeof(Elf32_Shdr));

        std::vector<uint8_t> shstrtab;
        uint32_t shstr_offset = 0;
        uint32_t shstr_size = 0;
        if (shstr < sh_cnt) {
            shstr_offset = shdrs[shstr].sh_offset;
            shstr_size = shdrs[shstr].sh_size;
            shstrtab.assign(elf.data.data() + shstr_offset, elf.data.data() + shstr_offset + shstr_size);
        }

        if (elf.data.size() < foff)
            elf.data.resize(foff, 0);

        uint32_t blob_offset = (uint32_t)elf.data.size();
        elf.data.insert(elf.data.end(), blob.begin(), blob.end());

        Elf32_Phdr new_load = {};
        new_load.p_type = PT_LOAD;
        new_load.p_offset = blob_offset;
        new_load.p_vaddr = va;
        new_load.p_paddr = va;
        new_load.p_filesz = (uint32_t)blob.size();
        new_load.p_memsz = (uint32_t)blob.size();
        new_load.p_flags = PF_R | PF_X;
        new_load.p_align = 0x1000;
        phdrs.push_back(new_load);

        uint32_t new_ph_off = aup32((uint32_t)elf.data.size(), 4);
        elf.data.resize(new_ph_off);

        uint32_t ph_table_size = (uint32_t)(phdrs.size() * sizeof(Elf32_Phdr));

        for (Elf32_Phdr& p : phdrs) {
            if (p.p_type == PT_LOAD && p.p_offset == blob_offset && p.p_vaddr == va) {
                p.p_filesz = (new_ph_off + ph_table_size) - blob_offset;
                p.p_memsz = p.p_filesz;
            }
            if (p.p_type == PT_PHDR) {
                p.p_offset = new_ph_off;
                p.p_vaddr = va + (new_ph_off - blob_offset);
                p.p_paddr = p.p_vaddr;
                p.p_filesz = ph_table_size;
                p.p_memsz = ph_table_size;
                p.p_align = 4;
            }
        }
        for (const Elf32_Phdr& p : phdrs) {
            size_t pos = elf.data.size();
            elf.data.resize(pos + sizeof(p));
            memcpy(elf.data.data() + pos, &p, sizeof(p));
        }
        uint32_t new_name_idx = shstr_size;  
        uint32_t new_shstr_off = aup32((uint32_t)elf.data.size(), 4);
        elf.data.resize(new_shstr_off);
        elf.data.insert(elf.data.end(), shstrtab.begin(), shstrtab.end());
        for (char c : std::string(".prot")) elf.data.push_back(c);
        elf.data.push_back(0);
        uint32_t new_shstr_size = shstr_size + 7;
        if (shstr < (int)shdrs.size()) {
            shdrs[shstr].sh_offset = new_shstr_off;
            shdrs[shstr].sh_size = new_shstr_size;
        }
        Elf32_Shdr new_shdr = {};
        new_shdr.sh_name = new_name_idx;
        new_shdr.sh_type = SHT_PROGBITS;
        new_shdr.sh_flags = (uint32_t)(SHF_ALLOC | SHF_EXECINSTR);
        new_shdr.sh_addr = va;
        new_shdr.sh_offset = blob_offset;
        new_shdr.sh_size = (uint32_t)blob.size();
        new_shdr.sh_addralign = 4;
        shdrs.push_back(new_shdr);
        uint32_t new_sh_off = aup32((uint32_t)elf.data.size(), 4);
        elf.data.resize(new_sh_off);
        for (const Elf32_Shdr& s : shdrs) {
            size_t pos = elf.data.size();
            elf.data.resize(pos + sizeof(s));
            memcpy(elf.data.data() + pos, &s, sizeof(s));
        }
        Elf32_Ehdr* e = elf.e32();
        e->e_phoff = new_ph_off;
        e->e_phnum = (uint16_t)phdrs.size();
        e->e_shoff = new_sh_off;
        e->e_shnum = (uint16_t)shdrs.size();
    }

    void append64(ElfParser& elf, const std::vector<uint8_t>& blob, uint64_t foff, uint64_t va)
    {
        Elf64_Ehdr* ehdr = elf.e64();
        uint64_t ph_off = ehdr->e_phoff;
        uint64_t sh_off = ehdr->e_shoff;
        uint16_t ph_cnt = ehdr->e_phnum;
        uint16_t sh_cnt = ehdr->e_shnum;
        uint16_t shstr = ehdr->e_shstrndx;

        std::vector<Elf64_Phdr> phdrs(ph_cnt);
        for (uint16_t i = 0; i < ph_cnt; ++i)
            memcpy(&phdrs[i], elf.data.data() + ph_off + i * sizeof(Elf64_Phdr), sizeof(Elf64_Phdr));

        std::vector<Elf64_Shdr> shdrs(sh_cnt);
        for (uint16_t i = 0; i < sh_cnt; ++i)
            memcpy(&shdrs[i], elf.data.data() + sh_off + i * sizeof(Elf64_Shdr), sizeof(Elf64_Shdr));

        std::vector<uint8_t> shstrtab;
        uint64_t shstr_offset = 0;
        uint64_t shstr_size = 0;
        if (shstr < sh_cnt) {
            shstr_offset = shdrs[shstr].sh_offset;
            shstr_size = shdrs[shstr].sh_size;
            shstrtab.assign(elf.data.data() + shstr_offset, elf.data.data() + shstr_offset + shstr_size);
        }

        if ((uint64_t)elf.data.size() < foff)
            elf.data.resize((size_t)foff, 0);

        uint64_t blob_offset = elf.data.size();
        elf.data.insert(elf.data.end(), blob.begin(), blob.end());

        Elf64_Phdr new_load = {};
        new_load.p_type = PT_LOAD;
        new_load.p_flags = PF_R | PF_X;
        new_load.p_offset = blob_offset;
        new_load.p_vaddr = va;
        new_load.p_paddr = va;
        new_load.p_filesz = blob.size();
        new_load.p_memsz = blob.size();
        new_load.p_align = 0x1000;
        phdrs.push_back(new_load);

        uint64_t new_ph_off = aup64(elf.data.size(), 8);
        elf.data.resize(new_ph_off);

        uint64_t ph_table_size = phdrs.size() * sizeof(Elf64_Phdr);

        for (Elf64_Phdr& p : phdrs) {
            if (p.p_type == PT_LOAD && p.p_offset == blob_offset && p.p_vaddr == va) {
                p.p_filesz = (new_ph_off + ph_table_size) - blob_offset;
                p.p_memsz = p.p_filesz;
            }
            if (p.p_type == PT_PHDR) {
                p.p_offset = new_ph_off;
                p.p_vaddr = va + (new_ph_off - blob_offset);
                p.p_paddr = p.p_vaddr;
                p.p_filesz = ph_table_size;
                p.p_memsz = ph_table_size;
                p.p_align = 8;
            }
        }
        for (const Elf64_Phdr& p : phdrs) {
            size_t pos = elf.data.size();
            elf.data.resize(pos + sizeof(p));
            memcpy(elf.data.data() + pos, &p, sizeof(p));
        }

        uint32_t new_name_idx = (uint32_t)shstr_size; 
        uint64_t new_shstr_off = aup64(elf.data.size(), 8);
        elf.data.resize(new_shstr_off);
        elf.data.insert(elf.data.end(), shstrtab.begin(), shstrtab.end());
        for (char c : std::string(".prot")) elf.data.push_back(c);
        elf.data.push_back(0);
        uint64_t new_shstr_size = shstr_size + 7;

        if (shstr < (int)shdrs.size()) {
            shdrs[shstr].sh_offset = new_shstr_off;
            shdrs[shstr].sh_size = new_shstr_size;
        }
        Elf64_Shdr new_shdr = {};
        new_shdr.sh_name = new_name_idx;
        new_shdr.sh_type = SHT_PROGBITS;
        new_shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        new_shdr.sh_addr = va;
        new_shdr.sh_offset = blob_offset;
        new_shdr.sh_size = blob.size();
        new_shdr.sh_addralign = 8;
        shdrs.push_back(new_shdr);
        uint64_t new_sh_off = aup64(elf.data.size(), 8);
        elf.data.resize(new_sh_off);
        for (const Elf64_Shdr& s : shdrs) {
            size_t pos = elf.data.size();
            elf.data.resize(pos + sizeof(s));
            memcpy(elf.data.data() + pos, &s, sizeof(s));
        }
        Elf64_Ehdr* e = elf.e64();
        e->e_phoff = new_ph_off;
        e->e_phnum = (uint16_t)phdrs.size();
        e->e_shoff = new_sh_off;
        e->e_shnum = (uint16_t)shdrs.size();
    }
};
