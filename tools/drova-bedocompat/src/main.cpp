#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <unistd.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <thread>

#define LOG_TAG "DrovaTouch"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {
constexpr uintptr_t RVA_UPDATE_BODY = 0x3C30E18; // UpdateGameHandler + 4
constexpr uintptr_t RVA_TRY_GET = 0x3C31898;
constexpr uintptr_t RVA_ENABLE = 0x3C30558;
constexpr uintptr_t RVA_TOGGLE_CONSOLE = 0x3C31044;
constexpr uintptr_t RVA_ACTION_LEVEL = 0x39E444C;      // Awake lambda 8
constexpr uintptr_t RVA_ACTION_WEATHER = 0x39E4658;    // Awake lambda 9
constexpr uintptr_t RVA_ACTION_COSMETICS = 0x39E46C0;  // Awake lambda 10
constexpr uintptr_t RVA_ACTION_EQUIPMENT = 0x39E4AE8;  // Awake lambda 13

std::atomic<uint32_t> pending{0};
uintptr_t il2cpp_base = 0;
using Hook = void (*)(void*, void*, void**);
using Update = void (*)(void*, float, void*);
Update original_update = nullptr;

uintptr_t module_base(const char* soname) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512]; uintptr_t base=0;
    while (fgets(line,sizeof(line),f)) {
        if (strstr(line,soname)) { base=strtoull(line,nullptr,16); break; }
    }
    fclose(f); return base;
}

void run_action(uint32_t action) {
    void* handler=nullptr;
    auto try_get=reinterpret_cast<bool(*)(void**,void*)>(il2cpp_base+RVA_TRY_GET);
    if (!try_get(&handler,nullptr) || !handler) return;
    if (action==1) {
        reinterpret_cast<void(*)(void*,bool,void*)>(il2cpp_base+RVA_ENABLE)(handler,true,nullptr);
        reinterpret_cast<void(*)(void*,void*)>(il2cpp_base+RVA_TOGGLE_CONSOLE)(handler,nullptr);
    } else if (action==2) {
        reinterpret_cast<void(*)(void*,bool,void*)>(il2cpp_base+RVA_ENABLE)(handler,true,nullptr);
    } else {
        uintptr_t rva = action==3 ? RVA_ACTION_LEVEL : action==4 ? RVA_ACTION_WEATHER :
                        action==5 ? RVA_ACTION_COSMETICS : RVA_ACTION_EQUIPMENT;
        reinterpret_cast<void(*)(void*,void*)>(il2cpp_base+rva)(nullptr,nullptr);
    }
}

void update_hook(void* self,float dt,void* method) {
    uint32_t action=pending.exchange(0);
    if (action) run_action(action);
    original_update(self,dt,method);
}

jobjectArray features(JNIEnv* env,jclass) {
    const char* items[]={
        "Category_Drova — меню разработчиков",
        "Button_Открыть консоль разработчиков",
        "Button_Включить чит-режим",
        "Button_Повысить уровень",
        "Button_Сменить погоду",
        "Button_Косметика",
        "Button_Стандартная экипировка"
    };
    jclass str=env->FindClass("java/lang/String");
    auto out=env->NewObjectArray(sizeof(items)/sizeof(items[0]),str,nullptr);
    for (jsize i=0;i<(jsize)(sizeof(items)/sizeof(items[0]));++i)
        env->SetObjectArrayElement(out,i,env->NewStringUTF(items[i]));
    return out;
}

jobjectArray settings(JNIEnv* env,jclass) {
    jclass str=env->FindClass("java/lang/String");
    return env->NewObjectArray(0,str,nullptr);
}

jboolean loaded(JNIEnv*,jclass) { return il2cpp_base ? JNI_TRUE : JNI_FALSE; }
void init(JNIEnv*,jclass,jobject,jobject,jobject,jobject) {}
jstring empty(JNIEnv* env,jclass) { return env->NewStringUTF(""); }
void changes(JNIEnv*,jclass,jobject,jint feature,jstring,jint,jlong,jboolean,jstring) {
    if (feature>=1 && feature<=6) pending.store((uint32_t)feature);
}

void install() {
    while (!(il2cpp_base=module_base("libil2cpp.so"))) sleep(1);
    void* core=dlopen("libCore.so",RTLD_NOW|RTLD_GLOBAL);
    auto hook=core ? reinterpret_cast<Hook>(dlsym(core,"A64HookFunction")) : nullptr;
    if (!hook) { LOGE("A64HookFunction unavailable"); return; }
    hook(reinterpret_cast<void*>(il2cpp_base+RVA_UPDATE_BODY),
         reinterpret_cast<void*>(update_hook),reinterpret_cast<void**>(&original_update));
    LOGI("Drova touch handlers installed");
}
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm,void*) {
    JNIEnv* env=nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env),JNI_VERSION_1_6)!=JNI_OK) return JNI_ERR;
    void* core=dlopen("libCore.so",RTLD_NOW|RTLD_GLOBAL);
    auto old_onload=core ? reinterpret_cast<jint(*)(JavaVM*,void*)>(dlsym(core,"JNI_OnLoad")) : nullptr;
    if (!old_onload || old_onload(vm,nullptr)<JNI_VERSION_1_6) return JNI_ERR;
    JNINativeMethod menu[]={
        {const_cast<char*>("GetFeatureList"),const_cast<char*>("()[Ljava/lang/String;"),reinterpret_cast<void*>(features)},
        {const_cast<char*>("SettingsList"),const_cast<char*>("()[Ljava/lang/String;"),reinterpret_cast<void*>(settings)},
        {const_cast<char*>("IsGameLibLoaded"),const_cast<char*>("()Z"),reinterpret_cast<void*>(loaded)},
        {const_cast<char*>("Init"),const_cast<char*>("(Landroid/content/Context;Landroid/widget/TextView;Landroid/widget/TextView;Landroid/widget/TextView;)V"),reinterpret_cast<void*>(init)},
        {const_cast<char*>("Icon"),const_cast<char*>("()Ljava/lang/String;"),reinterpret_cast<void*>(empty)},
        {const_cast<char*>("IconWebViewData"),const_cast<char*>("()Ljava/lang/String;"),reinterpret_cast<void*>(empty)}
    };
    jclass mc=env->FindClass("com/android/support/Menu");
    if (!mc || env->RegisterNatives(mc,menu,sizeof(menu)/sizeof(menu[0]))!=JNI_OK) return JNI_ERR;
    JNINativeMethod pref[]={
        {const_cast<char*>("Changes"),const_cast<char*>("(Landroid/content/Context;ILjava/lang/String;IJZLjava/lang/String;)V"),reinterpret_cast<void*>(changes)}
    };
    jclass pc=env->FindClass("com/android/support/Preferences");
    if (!pc || env->RegisterNatives(pc,pref,1)!=JNI_OK) return JNI_ERR;
    std::thread(install).detach();
    return JNI_VERSION_1_6;
}
