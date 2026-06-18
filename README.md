# aarch-packer

post-build protector for android .so libs. encrypts .text section with chacha20, rewrites internal call sites into pc-relative stubs, and patches .init_array so decryptor runs before JNI_OnLoad. works on arm32 and arm64, no root needed.

---

## how it works

### the protector (protector.exe)

takes finished .so, does everything needed and saves the result. can pass same file as input and output — will overwrite in place.

workflow (run64 / run32):

1. resolves skip-function ranges — looks by symtab, by `_prot_init_end` marker, by default takes 512 bytes and complains in log
2. collects list of exec sections (excluding .prot_text, .prot_data, .prot, .plt)
3. scans all functions for bl/blx calls inside the library
4. builds .prot blob in memory:
   - header: PROT_MAGIC (optionally xored with 0xC01EBA42) + region count
   - encrypted regions table: va + size for each exec section
   - redirects table: pc-relative offsets to stubs, encoded via nbitrev32 (NOT + 32-bit reverse)
   - target VA table for original calls
   - the stubs themselves: 16 bytes per call site
   - integrity table (INTEGRITY_MAGIC + xxhash32 per section, computed **after** patching call sites, **before** encryption)
   - optional: critical-functions table (CRIT_MAGIC)
   - optional: string table (STRTBL_MAGIC)
   - optional: library whitelist (WLIST_MAGIC, xxhash32 of .so basenames)
5. graph_breaker — inserts fake prologues and junk after branches. **currently disabled** — clobbers live instructions and causes SIGILL at runtime, will be rewritten
6. encrypts strings in .rodata-like sections (SHT_PROGBITS, alloc, not exec, not writable, not .prot_data) — length 4 to 512 bytes, separate xor key per string via xxhash32
7. patches call sites: every bl/blx is rewritten to jump into the stub in .prot
8. finalizes integrity hashes
9. encrypts exec sections with chacha20, skip ranges are skipped. each region gets own nonce, derived from region VA through a chacha20 block
10. critical functions get encrypted with a second layer (separate key, counter=1) on top of the first
11. appends .prot blob as a new PT_LOAD segment (PF_R|PF_X, align 0x1000) — rewrites phdrs, shdrs and shstrtab
12. patches .init_array:
    - arm64 PIE: rewrites .rela.dyn relocations covering .init_array — changes type to R_AARCH64_RELATIVE, reorders addends so _prot_init lands in slot 0
    - arm32 PIE: same thing with R_ARM_RELATIVE
    - non-PIE fallback: writes raw VA into first empty slot
13. wipes _prot_init, _prot_begin, _prot_init_end from .symtab (zeroes name and st_name). deliberately doesn't touch .dynsym — renaming there without rebuilding .hash chains breaks dlsym
14. optionally renames sections (XorShift64, 64-char names), then masks own sections: .prot_text → .text.0, .prot_data → .rodata0, .prot → .note0
15. optionally obfuscates symbol names in .symtab/.dynsym, rebuilds .hash table, zeroes DT_SONAME and DT_GNU_HASH

### the decryptor (prot_init.c)

`_prot_init` is an `__attribute__((constructor))` function linked straight into your .so.
linker puts it in .prot_text, then protector.exe places it first in .init_array.

runtime execution flow:

```
linker loads .so
  → processes .init_array relocations
  → _prot_init() runs first
      → do_decrypt()
          → dl_iterate_phdr() — look for library base address
          → find_prot_metadata() — scan PT_LOAD segments for PROT_MAGIC with 4-byte alignment
          → fallback: find_prot_metadata_maps() — parse /proc/self/maps, read .prot segment
          → derive keys: kdf_key(TK_A, TK_B, TK_C) / kdf_nonce(TN_A, TN_B, TN_C)
          → for each encrypted region:
              derive per-region nonce via rnonce() (chacha20 block with region_va >> 12)
              dreg(): sc_mmap_rwx() through SVC #0, memcpy, decrypt, memcpy back
              remember page range in g_seal[] for later mprotect
          → dcrit_all(): decrypt critical functions (crit key, counter=1)
          → dstr(): xor-decrypt strings in place (pages already RWX)
          → seal pages: sc_mprotect() g_seal[] → PROT_READ, then PROT_READ|EXEC
          → arm64: dsb ish / isb (icache invalidation)
          → wd_collect(): read integrity table, fill g_wd[] (VA + size + expected hash)
          → wd_start(): launch watchdog thread
          → g_decrypted = 1
  → _prot_init returns
  → remaining constructors
  → JNI_OnLoad on already-decrypted code
```

### why SVC #0 and not libc

on android with SELinux enforcing, `mprotect()` from libc is blocked for untrusted_app on file-backed exec pages. `mmap(MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, PROT_RWX)` replaces the whole mapping — this is allowed because it creates a new anonymous mapping, not changing permissions of existing one.

also, direct syscalls bypass frida hooks on libc wrappers.

syscall numbers:
- arm32: mmap2 = 192, mprotect = 125
- arm64: mmap = 222, mprotect = 226

### key scheme (3 shares)

key and nonce are never stored directly. they're derived from three shares through a chacha20 block:

```
key   = chacha20_block(state(TK_A, TK_B, counter=0x4B4446)) XOR TK_C
nonce = chacha20_block(state(TN_A, TN_B, counter=0x4E4F4E45)) XOR TN_C
```

per-region nonce:
```
region_nonce = chacha20_block(state(key, base_nonce, counter=region_va>>12)) XOR base_nonce
```

same exact kdf_key / kdf_nonce logic is duplicated byte-for-byte in `src/crypto.h` and `runtime/prot_init.c`. **if shares don't match — decryption won't pass.**

critical functions get a separate pair of shares: CK_A/B/C and CN_A/B/C, counter=1.

### watchdog

after decryption, `wd_start()` launches a detached thread that wakes up every ~1.3 sec and recomputes xxhash32 for each exec section. mismatch → `abort()`.

if a library whitelist is set — first /proc/self/maps gets parsed, basenames of .so files get hashed and checked against the whitelist. if all match (meaning it was a trusted tool like frida from the whitelist) — we update the hash instead of abort.

### call site stubs

arm64 (ADRP + ADD + BR, pc-relative, no relocations, works in PIE):
```asm
adrp x16, target_page
add  x16, x16, #lo12
br   x16
nop
```

arm32 (LDR + ADD + BX, pc-relative):
```asm
ldr  r12, [pc, #4]      ; load offset
add  r12, pc, r12       ; r12 = pc + (target|thumb - pc) = target|thumb
bx   r12                ; interwork arm<->thumb
.word (target|thumb_bit) - (stub_va + 12)
```

---

## building

### dependencies

- android ndk r21+ (tested on r25c)
- protector.exe — built from sources with cmake

### why -O0 -fno-builtin are mandatory for arm64

all decryptor functions (_prot_init, do_decrypt, dreg, dstr, cc20x etc) live in .prot_text via `__attribute__((section(".prot_text")))`. during decryption dreg() calls sc_mmap_rwx() which replaces .text pages with a new anonymous mapping. if compiler inlines memcpy, free or NEON from libc into .prot_text — these instructions end up on the same page we're remapping, and everything falls apart.

`-O0 -fno-builtin` forbid any such inlining. that's why prot_init.c gets compiled as a separate static lib with these flags.

`aligned(4096)` on _prot_init is a separate story — guarantees .prot_text doesn't share a page with .text.

### Android.mk

```makefile
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := prot_init_o0
LOCAL_SRC_FILES := ../../../../../runtime/prot_init.c
LOCAL_CFLAGS    := -O0 -fvisibility=default -fno-builtin -ffunction-sections -fdata-sections
ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
    LOCAL_CFLAGS += -mthumb
endif
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE           := yourlibname
LOCAL_SRC_FILES        := yourlib.cpp
LOCAL_LDLIBS           := -llog
LOCAL_CPPFLAGS         := -O2 -std=c++14 -fvisibility=hidden -ffunction-sections -fdata-sections
LOCAL_CFLAGS           := -O2 -fvisibility=hidden -ffunction-sections -fdata-sections
ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
    LOCAL_CPPFLAGS += -mthumb
    LOCAL_CFLAGS   += -mthumb
endif
LOCAL_STATIC_LIBRARIES := prot_init_o0

# -u needed so linker doesn't throw prot_init.o out of the archive — at link time
# nothing references _prot_init yet, protector.exe adds the .init_array entry later.
# without -u --gc-sections quietly drops the whole object and there's no decryptor in .so at all.
# --export-dynamic-symbol — so protector.exe can find VA even in a stripped library.
LOCAL_LDFLAGS := -Wl,-u,_prot_init \
                 -Wl,-u,_prot_begin \
                 -Wl,-u,_prot_init_end \
                 -Wl,--gc-sections \
                 -Wl,--export-dynamic-symbol=_prot_init \
                 -Wl,--export-dynamic-symbol=_prot_begin \
                 -Wl,--export-dynamic-symbol=_prot_init_end
include $(BUILD_SHARED_LIBRARY)
```

### Application.mk

```makefile
APP_ABI      := armeabi-v7a arm64-v8a
APP_PLATFORM := android-21
APP_OPTIM    := release
APP_STL      := c++_static
```

> repo currently has `APP_ABI := armeabi-v7a` — arm64 path still being finished. bring both ABIs back once arm64 works properly.

---

## usage

```
protector.exe [-v] [-c config.ini] input.so output.so
```

### config.ini

```ini
rename_sections  = true
rename_symbols   = true
encrypt_text     = true
skip_init_array  = true
obfuscate_magic  = true
graph_breaker    = false
name_seed        = 0x06AC82E3148BF15B

[critical]
# va  size  name
# 0x1234 0 critical_transform

[skip]
# _prot_init is usually auto-detected from symtab
# if not found — add manually:
# 0x2000 512 _prot_init

[whitelist]
# libfrida-agent.so
```

| option | what it does |
|---|---|
| `encrypt_text` | encrypts .text and all exec sections (except .plt) with chacha20 |
| `skip_init_array` | doesn't rename .init_array/.fini_array/.dynamic/.got |
| `rename_sections` | randomizes section names (64-char names, XorShift64) |
| `rename_symbols` | obfuscates non-exported symbols, rebuilds .hash |
| `obfuscate_magic` | xors PROT_MAGIC with 0xC01EBA42 |
| `graph_breaker` | fake prologues and junk after branches — **disabled, crashes** |
| `name_seed` | seed for name generator |
| `[critical]` | va, optional size, name — second chacha20 layer (crit key, counter=1) |
| `[skip]` | va, optional size, name — don't encrypt (decryptor functions) |
| `[whitelist]` | .so basenames — watchdog won't abort if all loaded libs are in the list |

skip-function size resolution order:
1. va + size given in config — use as is
2. va given, size not — look up in symtab by va
3. symtab found nothing — compute `_prot_init_end - va` if marker exists
4. fallback — 512 bytes, complains in log (add `_prot_init_end` for precision)
5. arm32 only: if even va is missing — search by hardcoded byte pattern in config.h

---

## expected output

```
[*] Loading libyourlib.so
[*] Arch: ARM64
[*] Auto-skip '.prot_text'
[*] Auto-skip '.prot_data'
[*] Auto-skip '.prot'
[*] Found 6 functions
[*] Found 12 call sites
[*] Encrypting strings...
[*] Encrypted 31 strings
[*] Patching 12 call sites...
[*] Finalizing integrity hashes (post-mutation)...
[*]   VA=0x10ac: 0x4f23a1b8
[*] Encrypting sections...
[*]   off=0x10ac size=0x298
[*] String table: 504 bytes
[*] _prot_init VA inferred from .prot_text: 0x2000
[*] init reloc slot[0] -> RELATIVE addend=0x2000  (_prot_init, runs first)
[*] stripped symbol '_prot_init' (symtab)
[*] masked section .prot_text -> .text.0
[+] Done! 19488 bytes
```

if you see `[!] _prot_init not found in symtab` — most likely you forgot `--export-dynamic-symbol=_prot_init` or prot_init_o0 didn't get linked (no `-u _prot_init`).

---

## logcat (tag: prot)

| log | meaning |
|---|---|
| `s` | _prot_init entered do_decrypt() |
| `rg` | .prot metadata found, starting decryption |
| `ds` | text decrypted, starting strings |
| `ok` | everything decrypted, watchdog launched |
| `b` | dl_iterate_phdr didn't find library base |
| `p0`–`p9` | .prot metadata not found (digit = g_maps_stage at moment of failure) |
| `m` | wrong magic in .prot header |
| `n` | wrong region count in header |
| `nw` | sc_mmap_rwx returned an error |
| `tamper` | watchdog caught a hash mismatch, abort() follows |

---

## keys

shares are stored in .prot_data and don't fall under encryption. need to change in **both** files — `src/crypto.h` and `runtime/prot_init.c` — otherwise runtime won't be able to decrypt.

- TK_A, TK_B, TK_C / TN_A, TN_B, TN_C — key and nonce shares for text encryption
- CK_A, CK_B, CK_C / CN_A, CN_B, CN_C — key and nonce shares for critical functions

---

## limitations

- **memory dump** — once _prot_init has run, decrypted code is visible in process memory. protects against static analysis of the .so file, not against a targeted runtime dump
- **extractNativeLibs=false** — supported. dl_iterate_phdr uses p_filesz (not p_memsz), which works correctly for APK-embedded libraries
- **arm64 page layout** — if _prot_init VA = 0x1000 (same page as .text), dreg() remaps the page it's running on itself and everything falls apart. check that output shows `_prot_init VA` >= 0x2000, and that -O0 -fno-builtin flags are actually applied to prot_init.c
- **graph_breaker** — disabled. current implementation clobbers real instructions (fake prologues after first ret, junk after B in thumb), which breaks reachable code. will be rewritten to only insert into inter-function padding
- **arm64 pattern** — PROT_INIT_PATTERN_ARM64 not implemented (TODO in code). skip VA must be resolved from symtab or _prot_init_end marker. arm32 pattern exists but isn't used on arm64 branch

---

## project structure

```
aarch-packer/
├── src/
│   ├── main.cpp            — entry point, argument parsing (-v, -c)
│   ├── protector.h         — Protector class: run32/run64, append32/append64,
│   │                         init_array patching, symbol wiping, section masking
│   ├── elf_parser.h        — ELF load/save, VA<->offset, function enumeration
│   ├── elf_types.h         — Elf32/Elf64 structs and ELF constants without system headers
│   ├── arch_arm32.h        — ARM32/Thumb2 BL/BLX scanner, pc-relative stub writer
│   ├── arch_arm64.h        — AArch64 BL scanner, ADRP+ADD+BR stub writer
│   ├── crypto.h            — chacha20 block/xor, 3-share KDF, per-region nonce,
│   │                         crit layer, XorShift64 name generator
│   ├── integrity.h         — xxhash32 implementation, table magic values
│   ├── string_enc.h        — .rodata string scanner, xor encryption, blob builder
│   ├── graph_breaker.h     — fake prologue and junk insertion (disabled)
│   ├── sec_renamer.h       — section name randomization (XorShift64, rewrites .shstrtab)
│   ├── sym_obfuscator.h    — symbol obfuscation, .hash rebuild, DT_SONAME wipe
│   └── config.h            — config.ini parser, CriticalFunc/SkipFunc/whitelist structs
├── runtime/
│   ├── prot_init.c         — runtime decryptor (_prot_init, do_decrypt, dreg, dstr,
│   │                         dcrit_all, watchdog, whitelist checker, direct syscalls)
│   └── Android.mk           — build rules for prot_init as a separate static lib
├── testlib/
│   ├── testlib.cpp         — test JNI library (strings, math, critical,
│   │                         self-check, tamper-detection test via mprotect + byte xor)
│   ├── Android.mk           — testlib build rules + prot_init_o0 linking
│   └── Application.mk       — ABI, platform, STL
└── config/
    └── config.ini           — example config
```
