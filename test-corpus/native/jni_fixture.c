/* UniRevLab-owned benign fixture for static ELF/JNI parser tests. */
#include <stddef.h>

const char *unirevlab_fixture_endpoint = "http://example.invalid/api?token=redacted-by-scanner";
/* Deliberately fake JWT-shaped value used only to verify hash/redaction behavior. */
const char *unirevlab_fixture_fake_token = "eyJabcdefghijk.abcdefghijkl.mnopqrstuvwxyz";

int JNI_OnLoad(void *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    volatile char buffer[16] = {0};
    return buffer[0] + 0x00010006;
}

void Java_com_example_NativeBridge_nativeCheck(void *env, void *thiz) {
    (void)env;
    (void)thiz;
    volatile char buffer[16] = {0};
    (void)buffer;
}

void unirevlab_register_natives_marker(void) {
    const char *marker = "RegisterNatives";
    (void)marker;
}
