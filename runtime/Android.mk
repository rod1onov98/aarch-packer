LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := prot_init_o0
LOCAL_SRC_FILES := prot_init.c
LOCAL_CFLAGS    := -O0 -fvisibility=hidden -fno-builtin
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE        := testlib
LOCAL_SRC_FILES     := testlib.cpp
LOCAL_LDLIBS        := -llog
LOCAL_CPPFLAGS      := -O2 -std=c++14 -fvisibility=hidden
LOCAL_CFLAGS        := -O2 -fvisibility=hidden
LOCAL_STATIC_LIBRARIES := prot_init_o0
include $(BUILD_SHARED_LIBRARY)