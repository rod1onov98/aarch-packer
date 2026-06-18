#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>

struct CriticalFunc { uint64_t va; uint32_t size; std::string name; };
struct SkipFunc     { uint64_t va; uint32_t size; std::string name; };

struct ProtConfig {
    bool     rename_sections  = true;
    bool     rename_symbols   = true;
    bool     encrypt_text     = true;
    bool     skip_init_array  = true;
    bool     obfuscate_magic  = true;
    // graph_breaker overwrites live instructions in-place (junk after branches,
    // fake prologues after the first ret) and corrupts real code -> SIGILL at
    // runtime. Disabled until rewritten to use inter-function padding only.
    bool     graph_breaker    = false;
    uint64_t name_seed        = 0x06AC82E3148BF15B;

    std::vector<CriticalFunc> critical_funcs;
    std::vector<SkipFunc>     skip_funcs;
    std::vector<std::string>  whitelist_libs;

    bool load(const std::string& path) {
        FILE* f = fopen(path.c_str(), "r");
        if (!f) return false;
        char line[512];
        enum { NONE, CRITICAL, SKIP, WHITELIST } sec = NONE;
        while (fgets(line, sizeof(line), f)) {
            int len = (int)strlen(line);
            while (len>0&&(line[len-1]=='\n'||line[len-1]=='\r'||line[len-1]==' ')) line[--len]='\0';
            if (!len || line[0]=='#') continue;
            if (line[0]=='[') {
                if      (!strncmp(line,"[critical]",10))  sec=CRITICAL;
                else if (!strncmp(line,"[skip]",6))       sec=SKIP;
                else if (!strncmp(line,"[whitelist]",11)) sec=WHITELIST;
                else                                       sec=NONE;
                continue;
            }
            if (sec==WHITELIST) {
                char*p=line;
                while(*p==' '||*p=='\t')p++;
                if(*p) whitelist_libs.push_back(std::string(p));
                continue;
            }
            if (sec==CRITICAL||sec==SKIP) {
                uint64_t va=0; uint32_t sz=0; char name[256]={};
                char*p=line;
                while(*p==' '||*p=='\t')p++;
                if(*p=='0'&&(*(p+1)=='x'||*(p+1)=='X')){p+=2;while(*p&&*p!=' '&&*p!='\t'){char c=*p++;va=va*16+(c>='a'?c-'a'+10:c>='A'?c-'A'+10:c-'0');}}
                else if(*p>='0'&&*p<='9'){while(*p>='0'&&*p<='9')va=va*10+(*p++-'0');}
                else continue;
                while(*p==' '||*p=='\t')p++;
                if(*p=='0'&&(*(p+1)=='x'||*(p+1)=='X')){p+=2;uint64_t s=0;while(*p&&*p!=' '&&*p!='\t'){char c=*p++;s=s*16+(c>='a'?c-'a'+10:c>='A'?c-'A'+10:c-'0');}sz=(uint32_t)s;}
                else{while(*p>='0'&&*p<='9')sz=sz*10+(*p++-'0');}
                while(*p==' '||*p=='\t')p++;
                int ni=0; while(*p&&ni<255)name[ni++]=*p++; name[ni]='\0';
                if(!va)continue;
                if(sec==CRITICAL) critical_funcs.push_back({va,sz,name});
                else              skip_funcs.push_back({va,sz,name});
            } else {
                char key[64]={},val[256]={};
                if(sscanf(line,"%63[^=] = %255[^\n]",key,val)!=2)continue;
                int kl=(int)strlen(key); while(kl>0&&key[kl-1]==' ')key[--kl]='\0';
                auto bv=[](const char*v){return !strcmp(v,"true")||!strcmp(v,"1")||!strcmp(v,"yes");};
                if     (!strcmp(key,"rename_sections")) rename_sections =bv(val);
                else if(!strcmp(key,"rename_symbols"))  rename_symbols  =bv(val);
                else if(!strcmp(key,"encrypt_text"))    encrypt_text    =bv(val);
                else if(!strcmp(key,"skip_init_array")) skip_init_array =bv(val);
                else if(!strcmp(key,"obfuscate_magic")) obfuscate_magic =bv(val);
                else if(!strcmp(key,"graph_breaker"))   graph_breaker   =bv(val);
                else if(!strcmp(key,"name_seed")){
                    name_seed=0;
                    const char*s=val;
                    if(s[0]=='0'&&(s[1]=='x'||s[1]=='X'))s+=2;
                    while(*s){char c=*s++;name_seed=name_seed*16+(c>='a'?c-'a'+10:c>='A'?c-'A'+10:c-'0');}
                }
            }
        }
        fclose(f); return true;
    }

    void print() const {
        printf("[config] rename_sections=%d rename_symbols=%d encrypt_text=%d\n", rename_sections,rename_symbols,encrypt_text);
        printf("[config] skip_init_array=%d obfuscate_magic=%d name_seed=0x%llx\n", skip_init_array,obfuscate_magic,(unsigned long long)name_seed);
        printf("[config] critical=%zu skip=%zu whitelist=%zu\n", critical_funcs.size(),skip_funcs.size(),whitelist_libs.size());
        for(auto&f:critical_funcs)
            printf("[config]   [critical] 0x%llx size=%u  %s\n", (unsigned long long)f.va,f.size,f.name.c_str());
        for(auto&f:skip_funcs)
            printf("[config]   [skip]     0x%llx size=%u  %s\n", (unsigned long long)f.va,f.size,f.name.c_str());
        for(auto&w:whitelist_libs)
            printf("[config]   [whitelist] %s\n", w.c_str());
    }
};

struct PatternResult { uint64_t file_off; uint32_t size; };

static inline PatternResult find_by_pattern(
    const std::vector<uint8_t>& data,
    const uint8_t* pattern, size_t pat_len)
{
    PatternResult res={0,0};
    if(!pat_len||data.size()<pat_len) return res;
    for(size_t i=0;i+pat_len<=data.size();i++){
        if(memcmp(data.data()+i,pattern,pat_len)==0){
            res.file_off=(uint64_t)i;
            res.size=256;
            return res;
        }
    }
    return res;
}

// not used, but still not removed
static const uint8_t PROT_INIT_PATTERN_ARM32[] = {
    0xF0,0xB5,0x03,0xAF,0x2D,0xE9,0x00,0x0F,
    0x81,0xB0,0x2D,0xED,0x10,0x8B,0xAD,0xF5,
    0x90,0x5D,0x82,0xB0,0x6C,0x46,0x6F,0xF3,
    0x03,0x04,0xA5,0x46,0x0F,0xF6,0x80,0x30
};
static const size_t PROT_INIT_PATTERN_ARM32_LEN = sizeof(PROT_INIT_PATTERN_ARM32);

// static const uint8_t PROT_INIT_PATTERN_ARM64[] = { /* TODO */ };
// static const size_t  PROT_INIT_PATTERN_ARM64_LEN = 0;
