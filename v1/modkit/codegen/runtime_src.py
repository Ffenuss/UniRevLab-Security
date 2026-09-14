"""Static (game-independent) C++ runtime shipped verbatim into every generated module."""

from __future__ import annotations

MODKIT_HPP = r"""#pragma once
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
"""

MODKIT_CPP = r"""// ---------------------------------------------------------------------------
//  modkit runtime implementation. Nothing in here is generated per project.
// ---------------------------------------------------------------------------
#include "modkit.hpp"

#include <chrono>
#include <cerrno>
#include <cstdio>
#include <string>
#include <vector>
#include <fcntl.h>

#if MODKIT_HAVE_DOBBY
extern "C" int DobbyHook(void *address, void *replace_func, void **origin_func);
extern "C" int DobbyDestroy(void *address);
#endif

namespace modkit {

void *Jvm::vm_ptr = nullptr;

static Module g_module;
static Il2CppApi g_api;

std::atomic<void *> *instance_slots() {
    static std::atomic<void *> slots[kMaxInstanceSlots];
    return slots;
}

Module &self() { return g_module; }

uint64_t monotonic_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// -------------------------------------------------------------------- module

namespace {
struct FindCtx {
    const char *needle;
    Module *out;
};

int phdr_cb(struct dl_phdr_info *info, size_t, void *data) {
    auto *ctx = static_cast<FindCtx *>(data);
    if (!info->dlpi_name || !*info->dlpi_name) return 0;
    if (strcmp(info->dlpi_name, ctx->needle) != 0 && strstr(info->dlpi_name, ctx->needle) == nullptr)
        return 0;
    uintptr_t lo = ~(uintptr_t)0;
    size_t top = 0;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD) continue;
        lo = std::min(lo, static_cast<uintptr_t>(info->dlpi_addr + ph.p_vaddr));
        top = std::max(top, static_cast<size_t>(ph.p_vaddr + ph.p_memsz));
    }
    if (lo == ~(uintptr_t)0) return 0;
    ctx->out->base = lo;
    ctx->out->size = top;
    return 1;
}
}  // namespace

Module find_module(const char *soname) {
    // dl_iterate_phdr beats dladdr/dlopen here: some OEM linkers hand back a
    // second link_map for an already-mapped library, which shifts the base.
    FindCtx ctx{soname, &g_module};
    g_module = Module{};
    dl_iterate_phdr(phdr_cb, &ctx);
    return g_module;
}

bool wait_for_module(const char *soname, Module *out, int timeout_ms) {
    for (int waited = 0; waited <= timeout_ms; waited += 100) {
        Module m = find_module(soname);
        if (m.found()) {
            if (out) *out = m;
            LOGI("%s @ %p (+0x%zx)", soname, (void *)m.base, m.size);
            return true;
        }
        usleep(100 * 1000);
    }
    return false;
}

uintptr_t rva(uint64_t relative) {
    if (!g_module.found()) find_module();
    return g_module.base + static_cast<uintptr_t>(relative);
}

// --------------------------------------------------------------- memory patch

void flush_icache(void *begin, void *end) {
    __builtin___clear_cache(static_cast<char *>(begin), static_cast<char *>(end));
#if defined(__aarch64__)
    // A patched page must be visible to the core that is about to execute it.
    __asm__ volatile("dsb ish; isb sy" ::: "memory");
#endif
}

static bool make_writable(uintptr_t start, size_t len) {
    const long ps = sysconf(_SC_PAGESIZE);
    uintptr_t lo = start & ~(uintptr_t)(ps - 1);
    uintptr_t hi = (start + len + ps - 1) & ~(uintptr_t)(ps - 1);
    // PROT_WRITE on a file-backed .text page would COW it, which is exactly what we
    // want inside our own process: the APK on disk is never touched.
    if (mprotect(reinterpret_cast<void *>(lo), hi - lo, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect(0x%lx, 0x%lx) = %s", (unsigned long)lo, (unsigned long)(hi - lo),
             strerror(errno));
        return false;
    }
    return true;
}

static void restore_protection(uintptr_t start, size_t len) {
    const long ps = sysconf(_SC_PAGESIZE);
    uintptr_t lo = start & ~(uintptr_t)(ps - 1);
    uintptr_t hi = (start + len + ps - 1) & ~(uintptr_t)(ps - 1);
    mprotect(reinterpret_cast<void *>(lo), hi - lo, PROT_READ | PROT_EXEC);
}

bool patch_memory(uintptr_t dst, const void *src, size_t len) {
    if (!dst || !src || !len) return false;
    if (!make_writable(dst, len)) return false;
    memcpy(reinterpret_cast<void *>(dst), src, len);
    flush_icache(reinterpret_cast<void *>(dst), reinterpret_cast<void *>(dst + len));
    restore_protection(dst, len);
    return true;
}

// ------------------------------------------------------------------- hooking

#if !MODKIT_HAVE_DOBBY
namespace {
void *alloc_exec(size_t n) {
    return mmap(nullptr, n, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

// b/bl/adr/adrp/ldr-literal are PC relative: copying them into a trampoline would
// break them, so refuse rather than corrupt the game.
bool prologue_relocatable(const uint32_t *insn, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        uint32_t w = insn[i];
        bool pc_rel = (w & 0x9F000000u) == 0x90000000u       // adrp
                   || (w & 0x7F000000u) == 0x10000000u       // adr
                   || (w & 0xFC000000u) == 0x94000000u       // bl
                   || (w & 0xFC000000u) == 0x14000000u       // b
                   || (w & 0xB8000000u) == 0x18000000u;      // ldr (literal)
        if (pc_rel) return false;
        if ((w & 0xFC000000u) == 0xD4000000u) return false;  // svc/brk/hvc + barriers
    }
    return true;
}

// ldr x16, #8 ; br x16 ; .quad target   (16 bytes of patch space)
bool write_abs_jump(uintptr_t at, uintptr_t target) {
    uint32_t tramp[4] = {0x58000050u, 0xD61F0200u, 0u, 0u};
    tramp[2] = static_cast<uint32_t>(target & 0xFFFFFFFFu);
    tramp[3] = static_cast<uint32_t>(target >> 32);
    return patch_memory(at, tramp, sizeof(tramp));
}

bool inline_hook(uintptr_t target, void *replace, void **origin) {
    constexpr size_t kStolen = 16;
    void *tramp = alloc_exec(64);
    if (tramp == MAP_FAILED) {
        LOGE("trampoline alloc failed: %s", strerror(errno));
        return false;
    }
    uint32_t insns[kStolen / 4];
    memcpy(insns, reinterpret_cast<void *>(target), sizeof(insns));
    if (!prologue_relocatable(insns, kStolen / 4)) {
        LOGW("refusing inline hook at 0x%lx: PC-relative prologue (link dobby for this one)",
             (unsigned long)target);
        munmap(tramp, 64);
        return false;
    }
    auto *tramp_u32 = static_cast<uint32_t *>(tramp);
    memcpy(tramp_u32, insns, sizeof(insns));
    if (!write_abs_jump(reinterpret_cast<uintptr_t>(tramp) + kStolen, target + kStolen)) {
        munmap(tramp, 64);
        return false;
    }
    if (origin) *origin = tramp;
    return write_abs_jump(target, reinterpret_cast<uintptr_t>(replace));
}
}  // namespace
#endif

bool install_hook(const HookDef &h) {
    uintptr_t target = h.absolute ? h.absolute : (h.rva ? rva(h.rva) : 0);
    if (!target) {
        LOGE("hook %s: no target address", h.name);
        return false;
    }
#if MODKIT_HAVE_DOBBY
    if (DobbyHook(reinterpret_cast<void *>(target), h.replace, h.original) != 0) {
        LOGE("DobbyHook(%s @ rva 0x%x) failed", h.name, h.rva);
        return false;
    }
#else
    if (!inline_hook(target, h.replace, h.original)) return false;
#endif
    LOGI("hooked %s @ rva 0x%x -> %p", h.name, h.rva, reinterpret_cast<void *>(target));
    return true;
}

void install_hooks(const HookDef *hooks, size_t count) {
    size_t ok = 0;
    for (size_t i = 0; i < count; ++i) ok += install_hook(hooks[i]) ? 1 : 0;
    LOGI("hooks: %zu/%zu installed (engine=%s)", ok, count,
         MODKIT_HAVE_DOBBY ? "dobby" : "inline");
}

// -------------------------------------------------------------- il2cpp bridge

static void *dlsym_any(const char *name) {
    static const char *libs[] = {MODKIT_TARGET_SO, "libunity.so", "libmain.so"};
    for (const char *l : libs) {
        void *h = dlopen(l, RTLD_NOW | RTLD_NOLOAD);
        if (!h) continue;
        if (void *s = dlsym(h, name)) return s;
    }
    return nullptr;
}

Il2CppApi &il2cpp() { return g_api; }

bool resolve_il2cpp_api() {
    Il2CppApi &a = g_api;
    a.thread_attach = dlsym_any("il2cpp_thread_attach");
    a.domain_get = dlsym_any("il2cpp_domain_get");
    a.class_from_name = dlsym_any("il2cpp_class_from_name");
    a.method_get_pointer = dlsym_any("il2cpp_method_get_pointer");
    a.resolved = a.thread_attach && a.class_from_name;
    LOGI("il2cpp api: attach=%p class_from_name=%p -> %s", a.thread_attach, a.class_from_name,
         a.resolved ? "reflection available" : "stripped, rva path only");
    return a.resolved;
}

void *runtime_thread_entry(void *) {
    Module m;
    if (!wait_for_module(MODKIT_TARGET_SO, &m, 60000)) {
        LOGE(MODKIT_TARGET_SO " never mapped — wrong package, or loaded too early");
        return nullptr;
    }
    resolve_il2cpp_api();
    game_install();  // implemented by the generated game.cpp
    return nullptr;
}

}  // namespace modkit
"""

JNI_MAIN = r"""// ---------------------------------------------------------------------------
//  JNI/native entry point. The same library supports two loading paths:
//  1) System.loadLibrary -> JNI_OnLoad + nativeInit (standalone/debug console),
//  2) DT_NEEDED -> ELF constructor when MODKIT_AUTOLOAD=1 (repacked APK flow).
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

static std::atomic<bool> g_started{false};
static std::atomic<bool> g_ready{false};

namespace {
void start_once() {
    bool expected = false;
    if (!g_started.compare_exchange_strong(expected, true)) return;
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

#if MODKIT_AUTOLOAD
__attribute__((constructor)) void modkit_autoload_constructor() {
    // A DT_NEEDED dependency is initialized before its host library completes
    // loading, so never touch target RVAs synchronously here. The worker waits
    // until MODKIT_TARGET_SO is visible in dl_iterate_phdr.
    start_once();
}
#endif
}  // namespace

extern "C" {

JNIEXPORT void JNICALL Java_###PKG_JNI###_ModKit_nativeInit(JNIEnv *, jclass) {
    start_once();
}

JNIEXPORT jboolean JNICALL Java_###PKG_JNI###_ModKit_nativeReady(JNIEnv *, jclass) {
    return g_ready.load() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL Java_###PKG_JNI###_ModKit_nativeStatus(JNIEnv *env, jclass) {
    char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"base\":\"0x%lx\",\"size\":\"0x%zx\",\"features\":%zu,\"ready\":%d}",
             (unsigned long)modkit::self().base, modkit::self().size, game::feature_count(),
             g_ready.load() ? 1 : 0);
    return env->NewStringUTF(buf);
}

JNIEXPORT void JNICALL Java_###PKG_JNI###_ModKit_nativeSetFeature(JNIEnv *env, jclass,
                                                                  jstring keyObj,
                                                                  jdouble value) {
    const char *key = env->GetStringUTFChars(keyObj, nullptr);
    game::set_feature_by_key(key, value);
    env->ReleaseStringUTFChars(keyObj, key);
}

JNIEXPORT jdouble JNICALL Java_###PKG_JNI###_ModKit_nativeGetFeature(JNIEnv *env, jclass,
                                                                     jstring keyObj) {
    const char *key = env->GetStringUTFChars(keyObj, nullptr);
    double v = game::get_feature_by_key(key);
    env->ReleaseStringUTFChars(keyObj, key);
    return v;
}

JNIEXPORT void JNICALL Java_###PKG_JNI###_ModKit_nativePushTouch(JNIEnv *, jclass,
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
"""

OVERLAY_HPP = r"""#pragma once
// ---------------------------------------------------------------------------
//  In-GL overlay: hooks eglSwapBuffers and renders a Dear ImGui menu using the
//  game's own GLES context, so no SYSTEM_ALERT_WINDOW permission is needed.
//  Touch arrives through the JNI bridge (the loader APK's transparent view) or,
//  with MODKIT_TOUCH_AINPUT, straight from AInputQueue.
// ---------------------------------------------------------------------------
#if MODKIT_OVERLAY
#include <atomic>

namespace game::overlay {

void start();
void stop();
void push_touch(int action, float x, float y);   // action: 0 down, 1 up, 2 move

std::atomic<bool> &visible();
std::atomic<float> &ui_scale();

}  // namespace game::overlay
#endif
"""

OVERLAY_CPP = r"""#if MODKIT_OVERLAY
#include "overlay.hpp"
#include "modkit.hpp"
#include "game.hpp"

#include <EGL/egl.h>
#include <GLES3/gl3.h>

#include <cerrno>
#include <deque>
#include <mutex>
#include <dlfcn.h>

#if MODKIT_HAS_IMGUI
#include "imgui.h"
#include "imgui_impl_opengl3.h"
#endif

namespace game::overlay {
namespace {

struct Touch {
    int action;
    float x, y;
};

constexpr size_t kMaxQueued = 64;

std::mutex g_touch_mu;
std::deque<Touch> g_touch;
std::atomic<bool> g_visible{true};
std::atomic<float> g_scale{2.0f};

using FnSwapBuffers = EGLBoolean (*)(EGLDisplay, EGLSurface);
FnSwapBuffers g_orig_swap = nullptr;
bool g_imgui_ready = false;
long g_frames = 0;

void viewport_size(int *w, int *h) {
    GLint box[4] = {0, 0, 1280, 720};
    glGetIntegerv(GL_VIEWPORT, box);
    *w = box[2] > 0 ? box[2] : 1280;
    *h = box[3] > 0 ? box[3] : 720;
}

void drain_touch(void *io_ptr) {
#if MODKIT_HAS_IMGUI
    auto *io = static_cast<ImGuiIO *>(io_ptr);
    if (!io) return;
    std::lock_guard<std::mutex> lk(g_touch_mu);
    while (!g_touch.empty()) {
        Touch t = g_touch.front();
        g_touch.pop_front();
        io->AddMouseButtonDown();  // mouse0 follows the single finger
        io->MousePos = ImVec2(t.x, t.y);
        if (t.action == 1) io->AddMouseButtonUp();
    }
#else
    (void)io_ptr;
    std::lock_guard<std::mutex> lk(g_touch_mu);
    g_touch.clear();
#endif
}

void render_frame() {
#if MODKIT_HAS_IMGUI
    if (!g_imgui_ready) {
        ImGui::CreateContext();
        ImGuiIO &io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.FontGlobalScale = g_scale.load();
        ImGui::StyleColorsDark();
        ImGuiStyle &st = ImGui::GetStyle();
        st.WindowRounding = 8.0f;
        st.FramePadding = ImVec2(10, 12);
        st.GrabMinSize = 22.0f;
        ImGui_ImplOpenGL3_Init("#version 300 es");
        g_imgui_ready = true;
    }
    ImGui_ImplOpenGL3_NewFrame();
    ImGuiIO &io = ImGui::GetIO();
    int w, h;
    viewport_size(&w, &h);
    io.DisplaySize = ImVec2((float)w, (float)h);
    io.DeltaTime = 1.0f / 60.0f;
    drain_touch(&io);

    if (g_visible.load()) {
        ImGui::SetNextWindowPos(ImVec2(24, 24), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(460, 340), ImGuiCond_FirstUseEver);
        ImGuiWindowFlags flags = ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings;
        if (ImGui::Begin("modkit", nullptr, flags)) {
            if (ImGui::SmallButton("hide")) g_visible.store(false);
            ImGui::SameLine();
            ImGui::TextUnformatted(game::status_line());
            ImGui::Separator();
            game::draw_features_ui();
        }
        ImGui::End();
    } else if (ImGui::Begin("###modkit_ball", nullptr,
                            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings)) {
        if (ImGui::Button("MOD")) g_visible.store(true);
        ImGui::End();
    } else {
        ImGui::End();
    }
    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
#endif
}

EGLBoolean hook_eglSwapBuffers(EGLDisplay dpy, EGLSurface surface) {
    render_frame();
    if ((++g_frames & 0xFF) == 1) LOGD("overlay alive: frame %ld", g_frames);
    return g_orig_swap ? g_orig_swap(dpy, surface) : EGL_TRUE;
}

}  // namespace

std::atomic<bool> &visible() { return g_visible; }
std::atomic<float> &ui_scale() { return g_scale; }

void push_touch(int action, float x, float y) {
    std::lock_guard<std::mutex> lk(g_touch_mu);
    g_touch.push_back({action, x, y});
    while (g_touch.size() > kMaxQueued) g_touch.pop_front();
}

void start() {
    void *egl = dlopen("libEGL.so", RTLD_NOW | RTLD_NOLOAD) ?: dlopen("libEGL.so", RTLD_NOW);
    auto *target = egl ? dlsym(egl, "eglSwapBuffers") : nullptr;
    if (!target) {
        LOGW("eglSwapBuffers unresolved — overlay off, JNI console still live");
        return;
    }
    // System library: hook the absolute address, no rva translation.
    modkit::HookDef h{0, reinterpret_cast<uintptr_t>(target), reinterpret_cast<void *>(target),
                      reinterpret_cast<void **>(&g_orig_swap), "eglSwapBuffers"};
    if (modkit::install_hook(h)) {
        LOGI("eglSwapBuffers hooked, overlay armed");
    } else {
        LOGW("eglSwapBuffers hook failed — use the JNI console or link dobby");
    }
}

void stop() { g_visible.store(false); }

}  // namespace game::overlay

#endif  // MODKIT_OVERLAY
"""
