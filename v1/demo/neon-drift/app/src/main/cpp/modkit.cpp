// ---------------------------------------------------------------------------
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
