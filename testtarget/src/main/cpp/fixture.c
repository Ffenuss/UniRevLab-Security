#include <jni.h>
#include <android/log.h>

static const char *k_fixture_marker = "unirevlab-native-regression-fixture";
static const char *k_process_probe_marker = "/proc/self/maps";

JNIEXPORT jstring JNICALL
Java_org_unirevlab_testtarget_NativeFixture_marker(JNIEnv *env, jclass clazz) {
    (void) clazz;
    __android_log_print(ANDROID_LOG_DEBUG, "UniRevLabTestTarget", "%s %s", k_fixture_marker, k_process_probe_marker);
    return (*env)->NewStringUTF(env, k_fixture_marker);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) vm;
    (void) reserved;
    return JNI_VERSION_1_6;
}
