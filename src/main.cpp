#include "protector.h"
#include <cstdio>
#include <cstring>

void usage(const char* p) {
    printf("Usage: %s [-v] [-c config.ini] <input.so> <output.so>\n\n", p);
    printf("Options:\n");
    printf("  -v              verbose output\n");
    printf("  -c config.ini   config file (default: looks for config.ini next to .exe)\n\n");
    printf("Config sections:\n");
    printf("  [critical]  - stronger encryption (ChaCha20 crit key)\n");
    printf("  [skip]      - do not encrypt (e.g. _prot_init)\n\n");
    printf("Example:\n");
    printf("  %s -c config.ini libyourlib.so libyourlib.so\n", p);
}

int main(int argc, char* argv[]) {
    printf("---------------- AARCH PACKER ----------------\n\n");
    bool        verbose     = false;
    const char* config_path = nullptr;
    const char* input       = nullptr;
    const char* output      = nullptr;

    for (int i=1;i<argc;i++) {
        if      (!strcmp(argv[i],"-v"))             verbose=true;
        else if (!strcmp(argv[i],"-c")&&i+1<argc)  config_path=argv[++i];
        else if (!input)  input =argv[i];
        else if (!output) output=argv[i];
    }
    if (!input||!output){usage(argv[0]);return 1;}

    try {
        Protector p; p.verbose=verbose;
        if (!config_path) {
            if (FILE* f=fopen("config.ini","r")){fclose(f);config_path="config.ini";}
        }
        if (config_path) {
            printf("[*] Config: %s\n", config_path);
            if (!p.cfg.load(config_path)) {
                fprintf(stderr,"[-] Failed to load: %s\n",config_path);
                return 1;
            }
        } else {
            printf("[*] No config, using defaults\n");
        }
        p.run(input,output);
    } catch(const std::exception& e) {
        fprintf(stderr,"[-] Error: %s\n",e.what()); return 1;
    }
    return 0;
}
