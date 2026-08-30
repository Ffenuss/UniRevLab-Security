/* UniRevLab-owned benign fixture for headless Ghidra regression tests. */
#include <stdint.h>

typedef struct {
    const char *name;
    const char *signature;
    void *fnPtr;
} JNINativeMethodFixture;

__attribute__((visibility("default"))) int native_add(void *env, void *thiz, int a, int b) {
    (void)env;
    (void)thiz;
    return a + b;
}

__attribute__((visibility("default")))
void Java_com_example_NativeBridge_nativeCheck(void *env, void *thiz) {
    (void)env;
    (void)thiz;
}

__attribute__((used, visibility("default")))
JNINativeMethodFixture unirevlab_methods[] = {
    {"nativeAdd", "(II)I", (void *)&native_add},
};

static uintptr_t code_registration_storage[] = {1, 2, 3, 4};
static uintptr_t metadata_registration_storage[] = {5, 6, 7, 8};

__attribute__((used, visibility("default")))
void *g_CodeRegistration = (void *)code_registration_storage;

__attribute__((used, visibility("default")))
void *g_MetadataRegistration = (void *)metadata_registration_storage;

__attribute__((visibility("default"), noinline))
void il2cpp_codegen_register(void *code, void *metadata, void *options) {
    volatile uintptr_t sink = (uintptr_t)code ^ (uintptr_t)metadata ^ (uintptr_t)options;
    (void)sink;
}

__attribute__((visibility("default"), noinline))
int fixture_branch(int value) {
    if (value > 7) {
        return native_add(0, 0, value, 4);
    }
    return value - 1;
}

__attribute__((visibility("default"), noinline))
void fixture_registration_call(void) {
    il2cpp_codegen_register(g_CodeRegistration, g_MetadataRegistration, 0);
}
