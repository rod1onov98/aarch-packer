# aarch-packer

runtime encryption tool for android native libraries (.so files). encrypts `.text` section with chacha20, decrypts on first execution using a custom `_prot_init` constructor. works on arm32 and arm64 without root.

---

## how it works

### overview

the protector consists of two parts:

1. **protector.exe** — post-build tool (windows/linux) that takes your `.so`, encrypts the `.text` section with chacha20, adds a `.prot` segment with metadata, and patches `.init_array` to call `_prot_init` on load.

2. **prot_init.c** — runtime decryptor compiled into your library. runs as a constructor before `JNI_OnLoad`, finds the encrypted region, decrypts it in-place using `MAP_FIXED + MAP_ANONYMOUS` syscall (bypasses SELinux `mprotect` restrictions on exec pages).

### encryption

- algorithm: **chacha20**
- key derivation: `TK_A XOR TK_B` → actual key, `TN_A XOR TN_B` → nonce
- keys stored in `.prot_data` section (excluded from encryption)
- string encryption: separate xor with per-string seed stored in `.prot` metadata

### decryption flow

```
library load
    → linker calls .init_array
    → _prot_init() runs
    → dl_iterate_phdr() finds library base
    → scan PT_LOAD segments for PROT_MAGIC (0x544F5250)
    → if not found, fallback to /proc/self/maps scan
    → decrypt .text region:
        malloc(page_size)
        memcpy encrypted bytes to tmp
        chacha20 decrypt in tmp
        mmap(MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, PROT_RWX) over original pages
        memcpy decrypted bytes back
        dsb ish / isb (arm64) or __builtin___clear_cache (arm32)
    → decrypt strings (xor in-place, pages already RWX)
    → JNI_OnLoad runs normally
```

### why MAP_FIXED instead of mprotect

on android (SELinux enforcing), `mprotect` is blocked for `untrusted_app` on file-backed executable pages. `mmap` with `MAP_FIXED|MAP_ANONYMOUS` replaces the mapping entirely — this is allowed because you're creating a new anonymous mapping, not changing permissions of an existing one.

### page layout requirement (arm64)

on arm64, `.prot_text` (where `_prot_init` lives) must be on a **different page** than `.text` (the encrypted section). otherwise `MAP_FIXED` overwrites the decryptor itself mid-execution.

solution: `__attribute__((aligned(4096)))` on `_prot_init` forces the linker to align `.prot_text` to a page boundary.

---

## building

### dependencies

- android ndk r21+ (tested on r25c)
- protector.exe (build from source with cmake, see `CMakeLists.txt`)

### arm32

`jni/Android.mk`:
```makefile
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := yourlibname
LOCAL_SRC_FILES := yourlib.cpp prot_init.c
LOCAL_LDLIBS    := -llog
LOCAL_CPPFLAGS  := -O2 -std=c++14 -fvisibility=hidden -mthumb
LOCAL_CFLAGS    := -O2 -fvisibility=hidden -mthumb -ffunction-sections -fdata-sections
LOCAL_LDFLAGS   := -Wl,--gc-sections
include $(BUILD_SHARED_LIBRARY)
```

`jni/Application.mk`:
```makefile
APP_ABI := armeabi-v7a
APP_OPTIM := release
```

### arm64

**important**: `prot_init.c` must be compiled with `-O0 -fno-builtin` to prevent the compiler from inlining `memcpy`/`free` into `.prot_text`, which would place NEON/libc code on the same page being remapped.

`jni/Android.mk`:
```makefile
LOCAL_PATH := $(call my-dir)

# compile prot_init separately with -O0 to prevent inlining into remapped pages
include $(CLEAR_VARS)
LOCAL_MODULE    := prot_init_o0
LOCAL_SRC_FILES := prot_init.c
LOCAL_CFLAGS    := -O0 -fvisibility=default -fno-builtin
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE           := yourlibname
LOCAL_SRC_FILES        := yourlib.cpp
LOCAL_LDLIBS           := -llog
LOCAL_CPPFLAGS         := -O2 -std=c++14 -fvisibility=hidden
LOCAL_CFLAGS           := -O2 -fvisibility=hidden
LOCAL_STATIC_LIBRARIES := prot_init_o0
LOCAL_LDFLAGS          := -Wl,--export-dynamic-symbol=_prot_init \
                          -Wl,--export-dynamic-symbol=_prot_begin
include $(BUILD_SHARED_LIBRARY)
```

`jni/Application.mk`:
```makefile
APP_ABI := arm64-v8a
APP_OPTIM := release
```

### both architectures

```makefile
APP_ABI := armeabi-v7a arm64-v8a
```

note: arm64 `Android.mk` works for both abis if you handle the `-mthumb` flag conditionally or use separate mk files.

---

## applying protection

```
protector.exe -c config/config.ini input.so output_protected.so
```

### config (config.ini)

```ini
rename_sections  = false
rename_symbols   = false
encrypt_text     = true
skip_init_array  = true
obfuscate_magic  = false
name_seed        = 0x06AC82E3148BF15B
```

| option | description |
|--------|-------------|
| `encrypt_text` | encrypt `.text` section with chacha20 |
| `skip_init_array` | don't encrypt `.init_array` (required) |
| `rename_sections` | rename section names to random strings |
| `rename_symbols` | obfuscate non-exported symbol names |
| `obfuscate_magic` | xor the `.prot` magic value |
| `name_seed` | seed for name generation |

---

## protector output

```
[*] Arch: ARM64
[*] Found 6 functions
[*] Encrypting strings...
[*] Encrypted 31 strings
[*] Encrypting sections...
[*]   off=0x10ac size=0x298
[*] String table: 504 bytes
[*] _prot_init VA inferred from .prot_text: 0x2000
[*] Patched .init_array[0] = 0x2000 (_prot_init)
[+] Done! 19488 bytes
```

if you see `[!] _prot_init not found in symtab` — make sure `--export-dynamic-symbol=_prot_init` is in your linker flags.

---

## runtime logs (logcat tag: `prot`)

| log | meaning |
|-----|---------|
| `s` | `_prot_init` started |
| `rg` | found `.prot` metadata, starting decryption |
| `ds` | decryption done, starting string decryption |
| `ok` | all done |
| `b` | failed to find library base via `dl_iterate_phdr` |
| `p0`-`p5` | failed to find `.prot` metadata (number = stage) |
| `m` | wrong magic in `.prot` header |
| `nw` | decryption failed (mmap error) |
| `mXX` | mmap error code |

---

## keys

keys are stored in `.prot_data` section and **excluded from string/text encryption**. to regenerate keys for your own build, replace the byte arrays in `prot_init.c`:

- `TK_A`, `TK_B` — text encryption key (XORed together)
- `TN_A`, `TN_B` — text nonce (XORed together)
- `CK_A`, `CK_B` — reserved for critical function encryption
- `CN_A`, `CN_B` — reserved nonce

use `PROT_MAGIC_RAW = 0x544F5250` as-is or enable `obfuscate_magic` in config.

---

## limitations

- **memory dump**: after `_prot_init` runs, decrypted code is visible in memory. this is a fundamental limitation of software-only protection. use this against static analysis, not against targeted runtime attacks.
- **extractNativeLibs=false**: supported. the protector uses `dl_iterate_phdr` with `p_filesz` (not `p_memsz`) to correctly handle APK-embedded libraries.
- **arm64 page layout**: `.prot_text` is forced to page boundary via `aligned(4096)`. if your build produces `_prot_init VA = 0x1000` (same page as `.text`), increase alignment or check compiler flags.

---

## project structure

```
protector/
├── src/
│   ├── main.cpp          — entry point
│   ├── protector.h       — main logic (arm32 + arm64 paths)
│   ├── crypto.h          — chacha20 implementation
│   ├── string_enc.h      — string encryption
│   ├── arch_arm32.h      — arm32 call site scanner
│   ├── arch_arm64.h      — arm64 call site scanner
│   ├── elf_parser.h      — ELF parsing utilities
│   └── config.h          — config file parser
├── runtime/
│   ├── prot_init.c       — runtime decryptor (arm32 + arm64)
│   └── Android.mk        — arm32 build file
├── config/
│   └── config.ini          — example config
└──
```
