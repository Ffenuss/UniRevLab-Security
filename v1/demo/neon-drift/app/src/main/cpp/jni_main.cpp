// ---------------------------------------------------------------------------
//  JNI entry point. The library is loaded inside the game process by the loader
//  APK (System.load) — no root, no frida-server, no zygote injection.
// ---------------------------------------------------------------------------
#include "modkit.hpp"
#include "game.hpp"
#if MODKIT_OVERLAY
#include "overlay.hpp"
#endif

#include <jni.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

static std::atomic<bool> g_ready{false};

extern "C" {

JNIEXPORT void JNICALL Java_com_neondrift_game_loader_ModKit_nativeInit(JNIEnv *, jclass) {
    std::thread([] {
        modkit::Module m;
        if (!modkit::wait_for_module(MODKIT_TARGET_SO, &m, 60000)) {
            LOGE(MODKIT_TARGET_SO " never appeared — is the target package correct?");
            return;
        }
        modkit::resolve_il2cpp_api();
        game::install();
        g_ready.store(true);
#if MODKIT_OVERLAY
        game::overlay::start();
#endif
        LOGI("modkit ready: %zu features", game::feature_count());
    }).detach();
}

JNIEXPORT jboolean JNICALL Java_com_neondrift_game_loader_ModKit_nativeReady(JNIEnv *, jclass) {
    return g_ready.load() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL Java_com_neondrift_game_loader_ModKit_nativeStatus(JNIEnv *env, jclass) {
    char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"base\":\"0x%lx\",\"size\":\"0x%zx\",\"features\":%zu,\"ready\":%d}",
             (unsigned long)modkit::self().base, modkit::self().size, game::feature_count(),
             g_ready.load() ? 1 : 0);
    return env->NewStringUTF(buf);
}

// Text console path — works even with the GL overlay disabled.
JNIEXPORT void JNICALL Java_com_neondrift_game_loader_ModKit_nativeSetFeature(JNIEnv *env, jclass,
                                                                  jstring keyObj,
                                                                  jdouble value) {
    const char *key = env->GetStringUTFChars(keyObj, nullptr);
    game::set_feature_by_key(key, value);
    env->ReleaseStringUTFChars(keyObj, key);
}

JNIEXPORT jdouble JNICALL Java_com_neondrift_game_loader_ModKit_nativeGetFeature(JNIEnv *env, jclass,
                                                                     jstring keyObj) {
    const char *key = env->GetStringUTFChars(keyObj, nullptr);
    double v = game::get_feature_by_key(key);
    env->ReleaseStringUTFChars(keyObj, key);
    return v;
}

JNIEXPORT void JNICALL Java_com_neondrift_game_loader_ModKit_nativePushTouch(JNIEnv * /*env*/, jclass,
                                                                 jint action, jfloat x, jfloat y) {
#if MODKIT_OVERLAY
    game::overlay::push_touch(action, x, y);
#endif
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    modkit::Jvm::set(vm);
    return JNI_VERSION_1_6;
}

}  // extern "C"
