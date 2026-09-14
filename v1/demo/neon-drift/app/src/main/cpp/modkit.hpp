#pragma once
// ---------------------------------------------------------------------------
//  modkit runtime — module base, code patching, hooking, feature ABI.
//  The per-project, generated half lives in game.hpp / game.cpp / features.inc.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <pthread.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <android/log.h>

#ifndef MODKIT_TAG
#define MODKIT_TAG "modkit"
#endif
#ifndef MODKIT_TARGET_SO
#define MODKIT_TARGET_SO "libil2cpp.so"
#endif
#ifndef MODKIT_HAVE_DOBBY
#define MODKIT_HAVE_DOBBY 0
#endif

#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, MODKIT_TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO,  MODKIT_TAG, __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN,  MODKIT_TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, MODKIT_TAG, __VA_ARGS__))

namespace modkit {

// ---------------------------------------------------------------- feature ABI

enum FKind : uint8_t {
    F_TOGGLE = 0,      // bool field / bool setter
    F_SLIDER,          // numeric, value within [lo,hi]
    F_VALUE_SET,       // numeric write through a managed setter
    F_FIELD_WRITE,     // raw write at this + off
    F_STATIC_WRITE,    // raw write at absolute rva (static field storage)
    F_CONST_RETURN,    // prologue replaced by `mov w0/x0, #imm; ret`
    F_HOOK,            // native callback, switchable
    F_ACTION,          // parameterless call
};

enum FFlag : uint8_t {
    F_NONE = 0,
    F_NEEDS_INSTANCE = 1 << 0,
    F_IS_STATIC = 1 << 1,
    F_DEFAULT_ON = 1 << 2,
};

struct FeatureDef {
    uint16_t id;
    const char *key;        // stable id, also the config file key
    const char *label;      // menu text
    const char *group;
    uint8_t kind;
    uint8_t flags;
    int16_t slot;           // instance slot index, -1 when unused
    uint32_t rva;           // method rva (or storage rva for static writes)
    int32_t off;            // field offset for raw writes
    uint8_t width;          // 1/2/4/8 bytes for writes, argc for hooks
    double def, lo, hi;
    const uint8_t *patch;   // F_CONST_RETURN payload; original bytes are captured at install
    uint16_t patch_len;
};

struct HookDef {
    uint32_t rva;           // translated against the module base at install time
    uintptr_t absolute;     // non-zero wins: hook this address directly (system libs)
    void *replace;
    void **original;
    const char *name;
};

// ------------------------------------------------------------------- instance

constexpr int kMaxInstanceSlots = 16;
std::atomic<void *> *instance_slots();

inline void *instance(int slot) {
    if (slot < 0 || slot >= kMaxInstanceSlots) return nullptr;
    return instance_slots()[slot].load(std::memory_order_acquire);
}

inline void set_instance(int slot, void *obj) {
    if (slot < 0 || slot >= kMaxInstanceSlots) return;
    instance_slots()[slot].store(obj, std::memory_order_release);
}

// -------------------------------------------------------------------- module

struct Module {
    uintptr_t base = 0;
    size_t size = 0;
    bool found() const { return base != 0; }
};

Module &self();
Module find_module(const char *soname = MODKIT_TARGET_SO);
bool wait_for_module(const char *soname, Module *out, int timeout_ms);
uintptr_t rva(uint64_t relative);

// --------------------------------------------------------------- memory patch

bool patch_memory(uintptr_t dst, const void *src, size_t len);
void flush_icache(void *begin, void *end);

// Plain write to managed heap / data pages (fields, static storage). No mprotect:
// those pages are already writable inside our own process.
inline bool write_data(uintptr_t dst, const void *src, size_t len) {
    if (!dst || !src || !len) return false;
    memcpy(reinterpret_cast<void *>(dst), src, len);
    return true;
}

// ------------------------------------------------------------------- hooking
// dobby (third_party/dobby) is preferred; without it the built-in arm64 prologue
// hooker runs, and it refuses to move PC-relative instructions.
bool install_hook(const HookDef &h);
void install_hooks(const HookDef *hooks, size_t count);

// -------------------------------------------------------------- il2cpp bridge

struct Il2CppApi {
    bool resolved = false;
    void *thread_attach = nullptr;
    void *domain_get = nullptr;
    void *class_from_name = nullptr;
    void *method_get_pointer = nullptr;
};
Il2CppApi &il2cpp();
bool resolve_il2cpp_api();

// ----------------------------------------------------------------- lifecycle

void *runtime_thread_entry(void *);
inline void start_runtime() {
    pthread_t t;
    pthread_create(&t, nullptr, runtime_thread_entry, nullptr);
    pthread_detach(t);
}

uint64_t monotonic_ms();

// Implemented by the generated game.cpp; declared here so the runtime stays independent.
extern "C" void game_install();

// Java VM handle, stored by JNI_OnLoad for the callbacks that need JNI.
using JavaVmHandle = void *;
struct Jvm {
    static void *vm_ptr;
    static void set(void *v) { vm_ptr = v; }
    static JavaVmHandle handle() { return reinterpret_cast<JavaVmHandle>(vm_ptr); }
};

}  // namespace modkit

// Native ABI of an il2cpp instance method: `this` in x0, then the arguments.
#define MODKIT_FN(decl, rva_) (reinterpret_cast<decl>(modkit::rva(rva_)))
#define MODKIT_CALL(decl, rva_, ...) (MODKIT_FN(decl, rva_)(__VA_ARGS__))
