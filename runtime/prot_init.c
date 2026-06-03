#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <unistd.h>
#include <jni.h>

#ifdef __arm__
#pragma GCC target("thumb")
#pragma GCC optimize("O2")
#endif
#ifdef __aarch64__
#pragma GCC optimize("O2")
#endif

#define PROT_SECTION  __attribute__((section(".prot_text"), noinline))
#define PROT_DATA     __attribute__((section(".prot_data")))
#define TAG_STR(v) char v[5]={(char)0x70,(char)0x72,(char)0x6f,(char)0x74,0}
#define LOG(pri,msg) do{TAG_STR(_t);__android_log_write((pri),_t,(msg));}while(0)

#define PROT_MAGIC_RAW  0x544F5250u
#define PROT_MAGIC      (PROT_MAGIC_RAW^0xC01EBA42u)
#define PROT_MAGIC_XOR  PROT_MAGIC_RAW
#define STRTBL_MAGIC    0x52545354u
#define STR_HASH_SEED   0xE00CB63Au
#define PAGE_SZ         4096u
#define PAGE_DN(x)      ((uintptr_t)(x)&~((uintptr_t)0xFFF))
#define PAGE_UP(x)      (((uintptr_t)(x)+(uintptr_t)0xFFF)&~((uintptr_t)0xFFF))

void _prot_init(void);

static const uint8_t PROT_DATA TK_A[32] = {0x09,0xCC,0x0E,0x29,0x5C,0x8D,0x99,0x13,0x05,0xF6,0xF2,0x3C,0x97,0x9E,0xC5,0xF3,0xE8,0x5A,0x31,0x3F,0xB2,0x1F,0x48,0x8D,0x65,0x59,0x8D,0xCE,0x6B,0x0C,0x26,0x2D };
static const uint8_t PROT_DATA TK_B[32] = {0x93,0x9A,0x6E,0x5C,0x33,0xAA,0xF4,0xBE,0x6E,0x4C,0xC4,0x4A,0x47,0x3E,0x83,0x7F,0x8D,0x6B,0xB9,0xE7,0xFB,0x22,0x42,0x99,0xF5,0x53,0x53,0xF9,0xA2,0x2B,0x5F,0x97 };
static const uint8_t PROT_DATA TN_A[12] = { 0x8E,0xB9,0x1D,0xC2,0x86,0xB2,0xDA,0x6D,0xA7,0x3A,0x9D,0xBB };
static const uint8_t PROT_DATA TN_B[12] = { 0x54,0x9A,0x4B,0x56,0x95,0xC5,0x0B,0x30,0x94,0x74,0x8D,0xF9 };
static const uint8_t PROT_DATA CK_A[32] = {0x47,0xAA,0x74,0x06,0x47,0xD2,0xBF,0x1B,0xFA,0x1E,0xD9,0x70,0x1E,0x26,0x19,0x75,0x2E,0x1D,0x61,0xED,0xA7,0x2C,0x1E,0xB8,0x4B,0x17,0x5C,0x08,0x13,0xC8,0xBB,0x34 };
static const uint8_t PROT_DATA CK_B[32] = {0x70,0x99,0xED,0x05,0xD0,0x29,0x2C,0x41,0xC3,0x83,0xDC,0x40,0xE3,0xBE,0x67,0xFD,0x49,0x7C,0x25,0x1D,0x48,0xF5,0x0C,0xBE,0x7E,0xB0,0x9F,0x6C,0x86,0xBE,0x65,0x12 };
static const uint8_t PROT_DATA CN_A[12] = { 0x74,0x3C,0x09,0x7F,0x0D,0x17,0x0E,0x94,0xC2,0x4F,0xBC,0x2C };
static const uint8_t PROT_DATA CN_B[12] = { 0x0E,0xF6,0x60,0x77,0x1D,0x2C,0xA1,0xD7,0x6E,0xAD,0xC8,0x77 };

typedef struct { uint8_t e[16]; uint16_t t, m; uint32_t v, en, ph, sh, f; uint16_t eh, pes, pen, ses, sen, sx; }E32H;
typedef struct { uint8_t e[16]; uint16_t t, m; uint32_t v; uint64_t en, ph, sh; uint32_t f; uint16_t eh, pes, pen, ses, sen, sx; }E64H;
typedef struct { uint32_t magic, n_regions; }PHdr;
typedef struct { uint32_t va_off, size; }PReg32;
typedef struct { uint64_t va_off, size; }PReg64;
typedef struct { uint32_t magic, n_strings; }SHdr;
typedef struct { uint32_t va_off, size, seed, pad; }SEntry;
typedef struct { uintptr_t base; const ElfW(Phdr)* phdr; ElfW(Half)phnum; }LObj;
typedef struct { const void* known; LObj obj; }FindObjCtx;
typedef struct { uintptr_t start, end; int readable; const char* path; size_t path_len; }MapLine;

static volatile int g_decrypted = 0;
static volatile int g_maps_stage = 0;

PROT_SECTION static void bk(uint8_t o[32], const uint8_t a[32], const uint8_t b[32]) { int i; for (i = 0; i < 32; i++)o[i] = a[i] ^ b[i]; }
PROT_SECTION static void bn(uint8_t o[12], const uint8_t a[12], const uint8_t b[12]) { int i; for (i = 0; i < 12; i++)o[i] = a[i] ^ b[i]; }

PROT_SECTION static uint32_t xxh32(const uint8_t* d, size_t n, uint32_t seed) {
    static const uint32_t P1 = 0x9E3779B1u, P2 = 0x85EBCA77u, P3 = 0xC2B2AE3Du, P4 = 0x27D4EB2Fu, P5 = 0x165667B1u;
#define R32(x,r)(((x)<<(r))|((x)>>(32-(r))))
    const uint8_t* p = d, * e = d + n; uint32_t h;
    if (n >= 16) {
        uint32_t v1 = seed + P1 + P2, v2 = seed + P2, v3 = seed, v4 = seed - P1; const uint8_t* lim = e - 16;
        do {
            uint32_t w; memcpy(&w, p, 4); v1 = R32(v1 + w * P2, 13) * P1; memcpy(&w, p + 4, 4); v2 = R32(v2 + w * P2, 13) * P1;
            memcpy(&w, p + 8, 4); v3 = R32(v3 + w * P2, 13) * P1; memcpy(&w, p + 12, 4); v4 = R32(v4 + w * P2, 13) * P1; p += 16;
        } while (p <= lim);
        h = R32(v1, 1) + R32(v2, 7) + R32(v3, 12) + R32(v4, 18);
    }
    else h = seed + P5;
    h += (uint32_t)n;
    while (p + 4 <= e) { uint32_t w; memcpy(&w, p, 4); h = R32(h + w * P3, 17) * P4; p += 4; }
    while (p < e) { uint8_t c = *p++; h = R32(h + c * P5, 11) * P1; }
    h ^= h >> 15; h *= P2; h ^= h >> 13; h *= P3; h ^= h >> 16;
#undef R32
    return h;
}
PROT_SECTION static uint32_t rol_(uint32_t x, int n) { return(x << n) | (x >> (32 - n)); }
#define QR_(a,b,c,d) a+=b;d^=a;d=rol_(d,16);c+=d;b^=c;b=rol_(b,12);a+=b;d^=a;d=rol_(d,8);c+=d;b^=c;b=rol_(b,7)
PROT_SECTION static void cc20b(uint32_t o[16], const uint32_t s[16]) {
    uint32_t x[16]; int i; memcpy(x, s, 64);
    for (i = 0; i < 10; i++) {
        QR_(x[0], x[4], x[8], x[12]); QR_(x[1], x[5], x[9], x[13]); QR_(x[2], x[6], x[10], x[14]); QR_(x[3], x[7], x[11], x[15]);
        QR_(x[0], x[5], x[10], x[15]); QR_(x[1], x[6], x[11], x[12]); QR_(x[2], x[7], x[8], x[13]); QR_(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 16; i++)o[i] = x[i] + s[i];
}
PROT_SECTION static void cc20x(uint8_t* d, size_t n, const uint8_t k[32], const uint8_t v[12], uint32_t ctr) {
    uint32_t s[16]; uint8_t ks[64]; size_t p = 0;
    s[0] = 0x61707865u; s[1] = 0x3320646eu; s[2] = 0x79622d32u; s[3] = 0x6b206574u;
    memcpy(s + 4, k, 32); s[12] = ctr; memcpy(s + 13, v, 12);
    while (p < n) {
        uint32_t b[16]; size_t i, c; cc20b(b, s); memcpy(ks, b, 64); s[12]++;
        c = (n - p < 64) ? (n - p) : 64; for (i = 0; i < c; i++)d[p + i] ^= ks[i]; p += c;
    }
}

#ifdef __arm__
PROT_SECTION static void* sc_mmap_rwx(void* addr, size_t len) {
    int _r;
    __asm__ volatile(
        "push {r4,r5,r7}\nmov r7,#192\nmov r0,%[a0]\nmov r1,%[a1]\n"
        "mov r2,#7\nmov r3,#50\nmov r4,#-1\nmov r5,#0\n"
        "svc #0\nmov %[res],r0\npop {r4,r5,r7}\n"
        : [res] "=r"(_r) : [a0] "r"((int)addr), [a1]"r"((int)len)
        : "r0", "r1", "r2", "r3", "r7", "memory");
    return (void*)_r;
}
#endif
#ifdef __aarch64__
PROT_SECTION static void* sc_mmap_rwx(void* addr, size_t len) {
    register long _x8 __asm__("x8") = 222;
    register long _x0 __asm__("x0") = (long)addr;
    register long _x1 __asm__("x1") = (long)len;
    register long _x2 __asm__("x2") = 7L;
    register long _x3 __asm__("x3") = 0x32L;
    register long _x4 __asm__("x4") = -1L;
    register long _x5 __asm__("x5") = 0L;
    __asm__ volatile("svc #0":"=r"(_x0) : "r"(_x8), "r"(_x0), "r"(_x1), "r"(_x2), "r"(_x3), "r"(_x4), "r"(_x5) : "memory");
    return (void*)_x0;
}
#endif

PROT_SECTION static int phdr_find_cb(struct dl_phdr_info* info, size_t size, void* data) {
    FindObjCtx* ctx = (FindObjCtx*)data;
    uintptr_t known = (uintptr_t)ctx->known;
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    ElfW(Half)i;
    (void)size;
    for (i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)* ph = &info->dlpi_phdr[i];
        uintptr_t start, end;
        if (ph->p_type != PT_LOAD || ph->p_filesz == 0)continue;
        start = base + (uintptr_t)ph->p_vaddr;
        end = start + (uintptr_t)ph->p_filesz;
        if (known >= start && known < end) {
            ctx->obj.base = base;
            ctx->obj.phdr = info->dlpi_phdr;
            ctx->obj.phnum = info->dlpi_phnum;
            return 1;
        }
    }
    return 0;
}

PROT_SECTION static int get_loaded_object(const void* known, LObj* out) {
    FindObjCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.known = known;
    dl_iterate_phdr(phdr_find_cb, &ctx);
    if (!ctx.obj.base || !ctx.obj.phdr || !ctx.obj.phnum)return 0;
    *out = ctx.obj;
    return 1;
}

PROT_SECTION static uint8_t* find_prot_metadata(const LObj* obj, uint32_t* prot_sz) {
    ElfW(Half)i;
    for (i = 0; i < obj->phnum; i++) {
        const ElfW(Phdr)* ph = &obj->phdr[i];
        uintptr_t va, sz, off;
        if (ph->p_type != PT_LOAD || ph->p_memsz < sizeof(PHdr))continue;
        va = (uintptr_t)ph->p_vaddr;
        sz = (uintptr_t)ph->p_memsz;
        for (off = 0; off + sizeof(PHdr) <= sz; off += 4) {
            uint8_t* p = (uint8_t*)(obj->base + va + off);
            uint32_t m = 0, n = 0;
            memcpy(&m, p, 4);
            if (m != PROT_MAGIC && m != PROT_MAGIC_XOR)continue;
            memcpy(&n, p + 4, 4);
            if (n == 0 || n > 10000)continue;
            if (prot_sz)*prot_sz = (uint32_t)(sz - off);
            return p;
        }
    }
    return NULL;
}

PROT_SECTION static uintptr_t parse_hex_ptr(const char** pp) {
    const char* p = *pp; uintptr_t v = 0;
    for (;; p++) {
        unsigned c = (unsigned char)*p;
        if (c >= '0' && c <= '9')v = (v << 4) + (c - '0');
        else if (c >= 'a' && c <= 'f')v = (v << 4) + (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')v = (v << 4) + (c - 'A' + 10);
        else break;
    }
    *pp = p; return v;
}

PROT_SECTION static int parse_maps_line(const char* line, const char* end, MapLine* out) {
    const char* p = line; int spaces = 0;
    memset(out, 0, sizeof(*out));
    out->start = parse_hex_ptr(&p);
    if (p >= end || *p != '-')return 0; p++;
    out->end = parse_hex_ptr(&p);
    if (p >= end || *p != ' ')return 0; p++;
    if (p >= end)return 0;
    out->readable = (*p == 'r');
    while (p < end && spaces < 4) { if (*p == ' ') { while (p < end&&* p == ' ')p++; spaces++; continue; }p++; }
    if (spaces >= 4 && p < end) {
        const char* q = end;
        while (q > p && (q[-1] == '\n' || q[-1] == '\r' || q[-1] == ' ' || q[-1] == '\t'))q--;
        out->path = p; out->path_len = (size_t)(q - p);
    }
    return out->end > out->start;
}

PROT_SECTION static int same_path(const MapLine* a, const MapLine* b) {
    if (!a->path || !b->path || !a->path_len || !b->path_len)return 0;
    return a->path_len == b->path_len && memcmp(a->path, b->path, a->path_len) == 0;
}

PROT_SECTION static uint8_t* scan_range_for_metadata(uintptr_t start, uintptr_t end, uint32_t* prot_sz) {
    uintptr_t p;
    if (end <= start + sizeof(PHdr))return NULL;
    for (p = start; p + sizeof(PHdr) <= end; p += 4) {
        uint32_t m = 0, n = 0;
        memcpy(&m, (void*)p, 4);
        if (m != PROT_MAGIC && m != PROT_MAGIC_XOR)continue;
        memcpy(&n, (void*)(p + 4), 4);
        if (n == 0 || n > 10000)continue;
        if (prot_sz)*prot_sz = (uint32_t)(end - p);
        return (uint8_t*)p;
    }
    return NULL;
}

PROT_SECTION static uint8_t* find_prot_metadata_maps(const void* known, uintptr_t base, uint32_t* prot_sz) {
    int fd; char* buf; ssize_t rd; const char* cur, * end;
    MapLine target; int have_target = 0; uintptr_t k = (uintptr_t)known;
    fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { g_maps_stage = 1; return NULL; }
    buf = (char*)malloc(131072);
    if (!buf) { close(fd); g_maps_stage = 2; return NULL; }
    rd = read(fd, buf, 131071); close(fd);
    if (rd <= 0) { free(buf); g_maps_stage = 3; return NULL; }
    buf[rd] = 0; cur = buf; end = buf + rd;
    while (cur < end) {
        const char* nl = (const char*)memchr(cur, '\n', (size_t)(end - cur));
        MapLine ml; if (!nl)nl = end;
        if (parse_maps_line(cur, nl, &ml) && k >= ml.start && k < ml.end && ml.path_len) { target = ml; have_target = 1; break; }
        cur = nl < end ? nl + 1 : end;
    }
    if (!have_target) { free(buf); g_maps_stage = 4; return NULL; }
    cur = buf;
    while (cur < end) {
        const char* nl = (const char*)memchr(cur, '\n', (size_t)(end - cur));
        MapLine ml; if (!nl)nl = end;
        if (parse_maps_line(cur, nl, &ml) && ml.readable &&
            (same_path(&ml, &target) || (ml.start >= base && ml.start < base + (uintptr_t)0x200000))) {
            uint8_t* ps = scan_range_for_metadata(ml.start, ml.end, prot_sz);
            if (ps) { free(buf); return ps; }
        }
        cur = nl < end ? nl + 1 : end;
    }
    free(buf); g_maps_stage = 5; return NULL;
}

PROT_SECTION __attribute__((noinline)) static int dreg(const LObj* obj, uint64_t va, uint64_t sz, const uint8_t* key, const uint8_t* nonce, uint32_t ctr) {
    uint8_t* p = (uint8_t*)(obj->base + (uintptr_t)va);
    uintptr_t ps = PAGE_DN(p), pe = PAGE_UP(p + sz);
    size_t pgsz = pe - ps;
    uint8_t* tmp;
    if (sz == 0 || pe <= ps)return 0;
    tmp = (uint8_t*)malloc(pgsz);
    if (!tmp)return 0;
    memcpy(tmp, (void*)ps, pgsz);
    cc20x(tmp + (p - (uint8_t*)ps), (size_t)sz, key, nonce, ctr);
    void* nm;
#ifdef __arm__
    {
        int _r;
        __asm__ volatile(
            "push {r4,r5,r7}
            mov r7, #192
            mov r0, % [a0]
            mov r1, % [a1]
            "
            "mov r2,#7
            mov r3, #50
            mov r4, # - 1
            mov r5, #0
            "
            "svc #0
            mov % [res], r0
            pop{ r4,r5,r7 }
            "
            : [res] "=r"(_r) : [a0] "r"((int)ps), [a1]"r"((int)pgsz)
            : "r0", "r1", "r2", "r3", "r7", "memory");
        nm = (void*)_r;
    }
#endif
#ifdef __aarch64__
    {
        register long _x8 __asm__("x8") = 222;
        register long _x0 __asm__("x0") = (long)ps;
        register long _x1 __asm__("x1") = (long)pgsz;
        register long _x2 __asm__("x2") = 7L;
        register long _x3 __asm__("x3") = 0x32L;
        register long _x4 __asm__("x4") = -1L;
        register long _x5 __asm__("x5") = 0L;
        __asm__ volatile("svc #0":"=r"(_x0) : "r"(_x8), "r"(_x0), "r"(_x1), "r"(_x2), "r"(_x3), "r"(_x4), "r"(_x5) : "memory");
        nm = (void*)_x0;
    }
#endif
    if ((uintptr_t)nm == ps) {
        memcpy((void*)ps, tmp, pgsz);
        free(tmp);
#ifdef __aarch64__
        __asm__ volatile("dsb ish\nisb" ::: "memory");
#else
        __builtin___clear_cache((char*)ps, (char*)pe);
#endif
        return 1;
    }
    {
        char en[5]; int e = -(int)(uintptr_t)nm; if (e < 0)e = 0;
        en[0] = 109; en[1] = 48 + ((e / 10) % 10); en[2] = 48 + (e % 10); en[3] = 0; LOG(6, en);
    }
    free(tmp); return 0;
}

PROT_SECTION static uint32_t skb(uint32_t seed, uint32_t idx) {
    uint8_t buf[8]; memcpy(buf, &seed, 4); memcpy(buf + 4, &idx, 4);
    uint32_t h = xxh32(buf, 8, STR_HASH_SEED); return(uint8_t)(h ^ (h >> 8) ^ (h >> 16) ^ (h >> 24));
}

PROT_SECTION static void dstr(const LObj* obj, uint8_t* ps, int is64, uint32_t prot_sz) {
    PHdr ph; uint8_t* p, * end; SHdr sh; SEntry* en; uint32_t i, j;
    memcpy(&ph, ps, sizeof(ph));
    p = ps + sizeof(PHdr);
    if (!is64)p += ph.n_regions * sizeof(PReg32); else p += ph.n_regions * sizeof(PReg64);
    end = ps + (prot_sz > 0 ? prot_sz : (1u << 18));
    while (p + sizeof(SHdr) < end) { uint32_t m = 0; memcpy(&m, p, 4); if (m == STRTBL_MAGIC)break; p += 4; }
    if (p + sizeof(SHdr) >= end)return;
    memcpy(&sh, p, sizeof(sh));
    if (!sh.n_strings || sh.n_strings > 200000)return;
    if (p + sizeof(SHdr) + (size_t)sh.n_strings * sizeof(SEntry) > end)return;
    en = (SEntry*)(p + sizeof(SHdr));
    for (i = 0; i < sh.n_strings; i++) {
        SEntry e; uint8_t* sp; uint32_t dl;
        memcpy(&e, &en[i], sizeof(e));
        if (!e.va_off || !e.size || e.size > 512)continue;
        sp = (uint8_t*)(obj->base + (uintptr_t)e.va_off);
        dl = e.size - 1;
        for (j = 0; j < dl; j++)sp[j] ^= skb(e.seed, j);
    }
}

PROT_SECTION static int do_decrypt(void) {
    LObj obj; uint8_t* ps; uint32_t prot_sz = 0; PHdr hdr;
    int is64; uint8_t* rp; uint8_t tkey[32], tnonce[12], ckey[32], cnonce[12];
    int decrypt_ok = 1; uint32_t i;
    if (g_decrypted)return 1;
    LOG(4, "s");
    if (!get_loaded_object((const void*)&_prot_init, &obj)) { LOG(6, "b"); return 0; }
    ps = find_prot_metadata_maps((const void*)&_prot_init, obj.base, &prot_sz);
    if (!ps)ps = find_prot_metadata(&obj, &prot_sz);
    if (!ps) { char e[4]; e[0] = 'p'; e[1] = (char)('0' + (g_maps_stage % 10)); e[2] = 0; LOG(6, e); return 0; }
    memcpy(&hdr, ps, sizeof(hdr));
    if (hdr.magic != PROT_MAGIC && hdr.magic != PROT_MAGIC_XOR) { LOG(6, "m"); return 0; }
    if (!hdr.n_regions || hdr.n_regions > 10000) { LOG(6, "n"); return 0; }
    is64 = (((uint8_t*)obj.base)[4] == 2);
    rp = ps + sizeof(PHdr);
    bk(tkey, TK_A, TK_B); bn(tnonce, TN_A, TN_B);
    bk(ckey, CK_A, CK_B); bn(cnonce, CN_A, CN_B);
    LOG(4, "rg");
    for (i = 0; i < hdr.n_regions; i++) {
        int dr_ok = 0;
        uint64_t va = 0, sz = 0;
        if (!is64) { PReg32 r; memcpy(&r, rp + i * sizeof(r), sizeof(r)); va = r.va_off; sz = r.size; }
        else { PReg64 r; memcpy(&r, rp + i * sizeof(r), sizeof(r)); va = r.va_off; sz = r.size; }
        if (!dreg(&obj, va, sz, tkey, tnonce, 0)) { decrypt_ok = 0; break; }
    }
    if (!decrypt_ok) { LOG(6, "nw"); memset(tkey, 0, 32); memset(tnonce, 0, 12); memset(ckey, 0, 32); memset(cnonce, 0, 12); return 0; }
    LOG(4, "ds");
    dstr(&obj, ps, is64, prot_sz);
    LOG(4, "ok");
    memset(tkey, 0, 32); memset(tnonce, 0, 12); memset(ckey, 0, 32); memset(cnonce, 0, 12);
    g_decrypted = 1; return 1;
}

__attribute__((visibility("default"), noinline, section(".prot_text")))
void _prot_begin(void); 

__attribute__((constructor, section(".prot_text"), aligned(4096), visibility("default")))
void _prot_init(void) { do_decrypt(); }

__attribute__((visibility("default"), noinline, section(".prot_text")))
void _prot_begin(void) { __asm__ volatile("nop"); }

__attribute__((visibility("default"), noinline, section(".prot_text")))
void _prot_init_end(void) { __asm__ volatile("nop"); }
