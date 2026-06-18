LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := prot_init_o0
# prot_init.c lives in the packer's runtime/ dir, two levels up from jni/
LOCAL_SRC_FILES := ../../../../../runtime/prot_init.c
LOCAL_CFLAGS    := -O0 -fvisibility=default -fno-builtin -ffunction-sections -fdata-sections
ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
    LOCAL_CFLAGS += -mthumb
endif
include $(BUILD_STATIC_LIBRARY)

# testlib — the actual test library. Links prot_init statically so _prot_init
# ends up inside libtestlib.so and gets wired into .init_array by protector.exe.
include $(CLEAR_VARS)
LOCAL_MODULE           := testlib
LOCAL_SRC_FILES        := testlib.cpp
LOCAL_LDLIBS           := -llog
LOCAL_CPPFLAGS         := -O2 -std=c++14 -fvisibility=hidden -ffunction-sections -fdata-sections
LOCAL_CFLAGS           := -O2 -fvisibility=hidden -ffunction-sections -fdata-sections
ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
    LOCAL_CPPFLAGS += -mthumb
    LOCAL_CFLAGS   += -mthumb
endif
LOCAL_STATIC_LIBRARIES := prot_init_o0

# Keep the protector's runtime symbols exported & undiscarded:
#  - -u forces the linker to PULL prot_init.o out of the static archive. Without
#    this, nothing references _prot_init at link time (the .init_array entry is
#    added later by protector.exe), so the whole object — and the .prot_text /
#    .prot_data sections — get dropped and the decryptor is simply absent.
#  - --export-dynamic-symbol keeps them in .dynsym so protector.exe can find the
#    VA even in a stripped .so.
#  - --gc-sections trims everything else; the -u symbols act as GC roots.
LOCAL_LDFLAGS := -Wl,-u,_prot_init \
                 -Wl,-u,_prot_begin \
                 -Wl,-u,_prot_init_end \
                 -Wl,--gc-sections \
                 -Wl,--export-dynamic-symbol=_prot_init \
                 -Wl,--export-dynamic-symbol=_prot_begin \
                 -Wl,--export-dynamic-symbol=_prot_init_end

include $(BUILD_SHARED_LIBRARY)
