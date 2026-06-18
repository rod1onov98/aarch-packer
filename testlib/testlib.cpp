#include <jni.h>
#include <android/log.h>
#include <string>
#include <cstdint>

#define LOG_TAG "testlib"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static int g_onload_status = 0;

__attribute__((noinline)) static int add_step(int a, int b) {
    return a + b;
}
__attribute__((noinline)) static int mul_step(int a, int b) {
    int acc = 0;
    for (int i = 0; i < b; i++) acc = add_step(acc, a);
    return acc;
}
__attribute__((noinline)) static int compute(int a, int b) {
    return mul_step(a, b);
}

extern "C" __attribute__((noinline, used, visibility("default")))
uint64_t critical_transform(uint64_t x) {
    uint64_t h = x ^ 0x9E3779B97F4A7C15ULL;
    h ^= h >> 30; h *= 0xBF58476D1CE4E5B9ULL;
    h ^= h >> 27; h *= 0x94D049BB133111EBULL;
    h ^= h >> 31;
    return h;
}

extern "C" JNIEXPORT jint JNICALL
Java_org_prottest_app_MainActivity_nativeOnLoadStatus(JNIEnv*, jclass) {
    return g_onload_status;
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_prottest_app_MainActivity_nativeStringTest(JNIEnv* env, jclass) {
    const char* a = "poop";
    const char* b = "poop2";
    std::string s;
    s += "s1="; s += a; s += " | s2="; s += b;
    LOGI("stringTest: %s", s.c_str());
    return env->NewStringUTF(s.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_org_prottest_app_MainActivity_nativeMathTest(JNIEnv*, jclass, jint a, jint b) {
    int r = compute(a, b); // 7*6 = 42 expected
    LOGI("mathTest: compute(%d,%d)=%d", a, b, r);
    return r;
}

extern "C" JNIEXPORT jlong JNICALL
Java_org_prottest_app_MainActivity_nativeCriticalTest(JNIEnv*, jclass, jlong x) {
    uint64_t r = critical_transform((uint64_t)x);
    LOGI("criticalTest: critical_transform(%lld)=%llu", (long long)x, (unsigned long long)r);
    return (jlong)r;
}

extern "C" JNIEXPORT jint JNICALL
Java_org_prottest_app_MainActivity_nativeSelfCheck(JNIEnv*, jclass) {
    volatile int acc = 0;
    for (int i = 1; i <= 100; i++) acc += i;
    return acc; // expect 5050
}

#include <sys/mman.h>
#include <unistd.h>
extern "C" JNIEXPORT jint JNICALL
Java_org_prottest_app_MainActivity_nativeCorruptSelf(JNIEnv*, jclass) {
    volatile uint8_t* target = (uint8_t*)(void*)&add_step;
    target = (uint8_t*)((uintptr_t)target & ~(uintptr_t)1); // clear thumb bit
    long ps = sysconf(_SC_PAGESIZE);
    void* page = (void*)((uintptr_t)target & ~((uintptr_t)ps - 1));
    if (mprotect(page, ps, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("corruptSelf: mprotect failed (W^X holding)");
        return -1;
    }
    target[0] ^= 0xFF;
    LOGI("corruptSelf: patched a .text byte, watchdog should abort soon");
    return 0;
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        LOGE("JNI_OnLoad: GetEnv failed");
        return JNI_ERR;
    }
    g_onload_status = 1;
    LOGI("JNI_OnLoad: OK (text already decrypted by _prot_init)");
    return JNI_VERSION_1_6;
}
