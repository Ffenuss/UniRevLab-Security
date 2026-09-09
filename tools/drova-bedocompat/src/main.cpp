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
constexpr uintptr_t RVA_GOD = 0x39EBAA0;
constexpr uintptr_t RVA_MAX_DAMAGE = 0x39E4098;
constexpr uintptr_t RVA_DONT_DIE = 0x39EA1F0;
constexpr uintptr_t RVA_INVINCIBLE = 0x39E3B10;
constexpr uintptr_t RVA_INFINITE_STAMINA = 0x39ED360;
constexpr uintptr_t RVA_INFINITE_FLOW = 0x39ED5D0;
constexpr uintptr_t RVA_NOCLIP = 0x39E3CC4;
constexpr uintptr_t RVA_NO_GAME_OVER = 0x39EFACC;
constexpr uintptr_t RVA_WEAPON_CRIT = 0x39E8F0C;
constexpr uintptr_t RVA_ATTRIBUTE_CRIT = 0x39E8D4C;
constexpr uintptr_t RVA_MONEY = 0x39E4308;
constexpr uintptr_t RVA_HEALTH = 0x39EC574;
constexpr uintptr_t RVA_MAX_HEALTH = 0x39EF7B0;

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
    } else if (action <= 6) {
        uintptr_t rva = action==3 ? RVA_ACTION_LEVEL : action==4 ? RVA_ACTION_WEATHER :
                        action==5 ? RVA_ACTION_COSMETICS : RVA_ACTION_EQUIPMENT;
        reinterpret_cast<void(*)(void*,void*)>(il2cpp_base+rva)(nullptr,nullptr);
    } else {
        // Every native IL2CPP call includes the hidden MethodInfo* as its last argument.
        switch (action) {
            case 7:  reinterpret_cast<void(*)(void*)>(il2cpp_base+RVA_GOD)(nullptr); break;
            case 8:  reinterpret_cast<void(*)(void*)>(il2cpp_base+RVA_MAX_DAMAGE)(nullptr); break;
            case 9:  reinterpret_cast<void(*)(void*)>(il2cpp_base+RVA_DONT_DIE)(nullptr); break;
            case 10: reinterpret_cast<void(*)(void*)>(il2cpp_base+RVA_INVINCIBLE)(nullptr); break;
            case 11: reinterpret_cast<void(*)(void*)>(il2cpp_base+RVA_INFINITE_STAMINA)(nullptr); break;
            case 12: reinterpret_cast<void(*)(void*)>(il2cpp_base+RVA_INFINITE_FLOW)(nullptr); break;
            case 13: reinterpret_cast<void(*)(float,void*)>(il2cpp_base+RVA_NOCLIP)(4.0f,nullptr); break;
            case 14: reinterpret_cast<void(*)(void*)>(il2cpp_base+RVA_NO_GAME_OVER)(nullptr); break;
            case 15: reinterpret_cast<void(*)(void*)>(il2cpp_base+RVA_WEAPON_CRIT)(nullptr); break;
            case 16: reinterpret_cast<void(*)(void*)>(il2cpp_base+RVA_ATTRIBUTE_CRIT)(nullptr); break;
            case 17: reinterpret_cast<void(*)(int,void*)>(il2cpp_base+RVA_MONEY)(1000,nullptr); break;
            case 18: reinterpret_cast<void(*)(int,void*)>(il2cpp_base+RVA_HEALTH)(100,nullptr); break;
            case 19: reinterpret_cast<void(*)(void*)>(il2cpp_base+RVA_MAX_HEALTH)(nullptr); break;
            default: break;
        }
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
        "Button_Стандартная экипировка",
        "Button_Бессмертие (God Mode)",
        "Button_Максимальный урон/атрибуты",
        "Button_Не умирать при нуле HP",
        "Button_Неуязвимость",
        "Button_Бесконечная выносливость",
        "Button_Бесконечный поток",
        "Button_NoClip (скорость 4x)",
        "Button_Отключить Game Over",
        "Button_Всегда крит оружием",
        "Button_Всегда крит атрибутом",
        "Button_Добавить 1000 монет",
        "Button_Восстановить 100 HP",
        "Button_Максимальное здоровье"
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
    if (feature>=1 && feature<=19) pending.store((uint32_t)feature);
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
