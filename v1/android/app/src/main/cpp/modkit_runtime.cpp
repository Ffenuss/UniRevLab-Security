#include <android/input.h>
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#include <EGL/egl.h>
#include <GLES2/gl2.h>

#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <string>
#include <vector>

#define MKLOGI(...) __android_log_print(ANDROID_LOG_INFO, "ModKitRuntime", __VA_ARGS__)
#define MKLOGW(...) __android_log_print(ANDROID_LOG_WARN, "ModKitRuntime", __VA_ARGS__)
#define MKLOGE(...) __android_log_print(ANDROID_LOG_ERROR, "ModKitRuntime", __VA_ARGS__)

namespace {

constexpr size_t kConfigCapacity = 16 * 1024;
constexpr uint32_t kMaxControls = 64;
constexpr uint32_t K_ACTION = 1;
constexpr uint32_t K_BOOL = 2;
constexpr uint32_t K_INT = 3;
constexpr uint32_t K_FLOAT = 4;
constexpr uint32_t K_PROBE_BOOL = 10;
constexpr uint32_t K_PROBE_INT = 11;
constexpr uint32_t K_PROBE_UINT = 12;
constexpr uint32_t K_PROBE_FLOAT = 13;
constexpr uint32_t F_ABI_IL2CPP = 1u << 8;
constexpr uint32_t F_INSTANCE = 1u << 9;
constexpr uint32_t F_RESOLVER_RETURN_PTR = 1u << 10;
constexpr uint32_t F_PROBE_READ_ONLY = 1u << 11;
constexpr uint32_t TAB_ALL = 0;
constexpr uint32_t TAB_COMBAT = 1;
constexpr uint32_t TAB_PLAYER = 2;
constexpr uint32_t TAB_RESOURCES = 3;
constexpr uint32_t TAB_WORLD = 4;
constexpr uint32_t TAB_DEBUG = 5;
constexpr uint32_t TAB_COUNT = 6;

#pragma pack(push, 1)
struct ConfigHeader {
    char magic[8];
    uint32_t version;
    uint32_t count;
    char target_so[64];
    char render_host[64];
    char title[64];
    uint8_t reserved[48];
};
struct ConfigEntry {
    uint32_t kind;
    uint32_t flags;
    uint64_t rva;
    uint64_t resolver_rva;
    float min_value;
    float max_value;
    float default_value;
    char id[48];
    char label[80];
    uint8_t reserved[4];
};
#pragma pack(pop)
static_assert(sizeof(ConfigHeader) == 256, "config header ABI");
static_assert(sizeof(ConfigEntry) == 168, "config entry ABI");

extern "C" __attribute__((section(".modkitcfg"), used, aligned(16), visibility("default")))
const unsigned char modkit_config_region[kConfigCapacity] = "MODKITCFG_RESERVED_V1";

struct Module {
    uintptr_t base = 0;
    const ElfW(Phdr) *phdr = nullptr;
    size_t phnum = 0;
    size_t span = 0;
    char name[192]{};
};

struct ControlState {
    float value = 0.0f;
};

struct ProbeState {
    void *klass = nullptr;
    uintptr_t object = 0;
    double value = 0.0;
    double previous = 0.0;
    uint32_t changes = 0;
    uint64_t last_sample_ms = 0;
    bool found = false;
};

const ConfigHeader *g_cfg = nullptr;
const ConfigEntry *g_entries = nullptr;
ControlState g_state[kMaxControls]{};
ProbeState g_probe[kMaxControls]{};
Module g_target{};
std::atomic<bool> g_ready{false};
std::atomic<bool> g_visible{true};
std::atomic<int> g_page{0};
std::atomic<int> g_tab{0};
std::atomic<int> g_menu_x{-1};
std::atomic<int> g_menu_y{-1};
std::atomic<int> g_touch_x{-1};
std::atomic<int> g_touch_y{-1};
std::atomic<int> g_touch_action{-1};
std::atomic<uint32_t> g_touch_seq{0};
std::atomic<int> g_drag_mode{0};  // 0 none, 1 panel, 2 collapsed icon
std::atomic<int> g_drag_dx{0};
std::atomic<int> g_drag_dy{0};
std::atomic<int> g_drag_start_x{0};
std::atomic<int> g_drag_start_y{0};
std::atomic<int> g_drag_moved{0};
std::atomic<int> g_pressed_index{-1};

using FnSwap = EGLBoolean (*)(EGLDisplay, EGLSurface);
using FnGetAction = int32_t (*)(const AInputEvent *);
using FnGetCoord = float (*)(const AInputEvent *, size_t);
FnSwap g_orig_swap = nullptr;
FnGetAction g_orig_get_action = nullptr;
FnGetCoord g_get_x = nullptr;
FnGetCoord g_get_y = nullptr;

bool valid_config() {
    static const char magic[8] = {'M','K','C','F','G','0','1','\0'};
    const auto *h = reinterpret_cast<const ConfigHeader *>(modkit_config_region);
    if (memcmp(h->magic, magic, sizeof(magic)) != 0 || (h->version != 2 && h->version != 3 && h->version != 4) || h->count > kMaxControls) {
        return false;
    }
    const size_t need = sizeof(ConfigHeader) + static_cast<size_t>(h->count) * sizeof(ConfigEntry);
    if (need > kConfigCapacity || h->target_so[0] == '\0') return false;
    g_cfg = h;
    g_entries = reinterpret_cast<const ConfigEntry *>(modkit_config_region + sizeof(ConfigHeader));
    for (uint32_t i = 0; i < h->count; ++i) g_state[i].value = g_entries[i].default_value;
    return true;
}

struct FindCtx { const char *needle; Module *out; };
int find_cb(struct dl_phdr_info *info, size_t, void *opaque) {
    auto *ctx = static_cast<FindCtx *>(opaque);
    if (!info->dlpi_name || !*info->dlpi_name) return 0;
    const char *base_name = strrchr(info->dlpi_name, '/');
    base_name = base_name ? base_name + 1 : info->dlpi_name;
    if (strcmp(base_name, ctx->needle) != 0 && strstr(info->dlpi_name, ctx->needle) == nullptr) return 0;
    ctx->out->base = static_cast<uintptr_t>(info->dlpi_addr);
    ctx->out->phdr = info->dlpi_phdr;
    ctx->out->phnum = info->dlpi_phnum;
    size_t top = 0;
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
        const auto &p = info->dlpi_phdr[i];
        if (p.p_type == PT_LOAD) top = top > p.p_vaddr + p.p_memsz ? top : p.p_vaddr + p.p_memsz;
    }
    ctx->out->span = top;
    snprintf(ctx->out->name, sizeof(ctx->out->name), "%s", info->dlpi_name);
    return 1;
}

bool find_module(const char *name, Module *out) {
    if (!name || !*name || !out) return false;
    *out = Module{};
    FindCtx ctx{name, out};
    dl_iterate_phdr(find_cb, &ctx);
    return out->base && out->phdr;
}

bool wait_module(const char *name, Module *out, int timeout_ms) {
    for (int elapsed = 0; elapsed <= timeout_ms; elapsed += 50) {
        if (find_module(name, out)) return true;
        usleep(50 * 1000);
    }
    return false;
}

uintptr_t dyn_ptr(const Module &m, uintptr_t v) {
    if (!v) return 0;
    if (v >= m.base && v < m.base + m.span) return v;
    return m.base + v;
}

bool mapped_range(const Module &m, uintptr_t address, size_t size) {
    if (!address || size == 0 || address > UINTPTR_MAX - size) return false;
    const uintptr_t end = address + size;
    for (size_t i = 0; i < m.phnum; ++i) {
        const auto &p = m.phdr[i];
        if (p.p_type != PT_LOAD) continue;
        if (m.base > UINTPTR_MAX - static_cast<uintptr_t>(p.p_vaddr)) continue;
        uintptr_t lo = m.base + static_cast<uintptr_t>(p.p_vaddr);
        if (lo > UINTPTR_MAX - static_cast<uintptr_t>(p.p_memsz)) continue;
        uintptr_t hi = lo + static_cast<uintptr_t>(p.p_memsz);
        if (lo <= address && end <= hi) return true;
    }
    return false;
}

int prot_for(const Module &m, uintptr_t address) {
    for (size_t i = 0; i < m.phnum; ++i) {
        const auto &p = m.phdr[i];
        if (p.p_type != PT_LOAD) continue;
        uintptr_t lo = m.base + p.p_vaddr;
        uintptr_t hi = lo + p.p_memsz;
        if (lo <= address && address < hi) {
            int prot = 0;
            if (p.p_flags & PF_R) prot |= PROT_READ;
            if (p.p_flags & PF_W) prot |= PROT_WRITE;
            if (p.p_flags & PF_X) prot |= PROT_EXEC;
            return prot;
        }
    }
    return PROT_READ;
}

bool executable_rva(const Module &m, uint64_t rva, uintptr_t *address_out = nullptr) {
    if (!rva || rva > static_cast<uint64_t>(UINTPTR_MAX)) return false;
    const uintptr_t urva = static_cast<uintptr_t>(rva);
    if (m.base > UINTPTR_MAX - urva) return false;
    const uintptr_t address = m.base + urva;
    if (!mapped_range(m, address, sizeof(uint32_t)) || !(prot_for(m, address) & PROT_EXEC)) return false;
    if (address_out) *address_out = address;
    return true;
}

bool patch_pointer(const Module &m, uintptr_t slot, void *replacement, void **original) {
    const long ps = sysconf(_SC_PAGESIZE);
    uintptr_t page = slot & ~(static_cast<uintptr_t>(ps) - 1u);
    int old_prot = prot_for(m, slot);
    if (mprotect(reinterpret_cast<void *>(page), static_cast<size_t>(ps), old_prot | PROT_WRITE) != 0) return false;
    auto **p = reinterpret_cast<void **>(slot);
    void *old = __atomic_load_n(p, __ATOMIC_ACQUIRE);
    if (original && !*original) *original = old;
    __atomic_store_n(p, replacement, __ATOMIC_RELEASE);
    __builtin___clear_cache(reinterpret_cast<char *>(page), reinterpret_cast<char *>(page + ps));
    mprotect(reinterpret_cast<void *>(page), static_cast<size_t>(ps), old_prot);
    return true;
}

bool hook_rela_table(const Module &m, const ElfW(Rela) *rel, size_t count,
                     const ElfW(Sym) *symtab, const char *strtab, size_t strsz,
                     const char *wanted, void *replacement, void **original) {
    if (!rel || !symtab || !strtab || count > 1000000 || strsz > 64 * 1024 * 1024) return false;
    if (!mapped_range(m, reinterpret_cast<uintptr_t>(rel), count * sizeof(ElfW(Rela))) ||
        !mapped_range(m, reinterpret_cast<uintptr_t>(strtab), strsz)) return false;
    for (size_t i = 0; i < count; ++i) {
        size_t sym_index = ELF64_R_SYM(rel[i].r_info);
        if (sym_index > 1000000) continue;
        uintptr_t sym_addr = reinterpret_cast<uintptr_t>(symtab + sym_index);
        if (!mapped_range(m, sym_addr, sizeof(ElfW(Sym)))) continue;
        const auto &sym = symtab[sym_index];
        if (sym.st_name >= strsz) continue;
        const char *name = strtab + sym.st_name;
        if (strncmp(name, wanted, 256) != 0) continue;
        uintptr_t slot = dyn_ptr(m, static_cast<uintptr_t>(rel[i].r_offset));
        if (!slot) continue;
        return patch_pointer(m, slot, replacement, original);
    }
    return false;
}

bool hook_import(const Module &m, const char *wanted, void *replacement, void **original) {
    const ElfW(Dyn) *dynamic = nullptr;
    for (size_t i = 0; i < m.phnum; ++i) {
        if (m.phdr[i].p_type == PT_DYNAMIC) {
            dynamic = reinterpret_cast<const ElfW(Dyn) *>(m.base + m.phdr[i].p_vaddr);
            break;
        }
    }
    if (!dynamic) return false;

    const char *strtab = nullptr;
    size_t strsz = 0;
    const ElfW(Sym) *symtab = nullptr;
    const ElfW(Rela) *jmprel = nullptr, *rela = nullptr;
    size_t pltrelsz = 0, relasz = 0, relaent = sizeof(ElfW(Rela));
    long pltrel = DT_RELA;
    for (const ElfW(Dyn) *d = dynamic; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
            case DT_STRTAB: strtab = reinterpret_cast<const char *>(dyn_ptr(m, d->d_un.d_ptr)); break;
            case DT_STRSZ: strsz = static_cast<size_t>(d->d_un.d_val); break;
            case DT_SYMTAB: symtab = reinterpret_cast<const ElfW(Sym) *>(dyn_ptr(m, d->d_un.d_ptr)); break;
            case DT_JMPREL: jmprel = reinterpret_cast<const ElfW(Rela) *>(dyn_ptr(m, d->d_un.d_ptr)); break;
            case DT_PLTRELSZ: pltrelsz = static_cast<size_t>(d->d_un.d_val); break;
            case DT_PLTREL: pltrel = static_cast<long>(d->d_un.d_val); break;
            case DT_RELA: rela = reinterpret_cast<const ElfW(Rela) *>(dyn_ptr(m, d->d_un.d_ptr)); break;
            case DT_RELASZ: relasz = static_cast<size_t>(d->d_un.d_val); break;
            case DT_RELAENT: relaent = static_cast<size_t>(d->d_un.d_val); break;
            default: break;
        }
    }
    if (!strtab || !strsz || !symtab || relaent != sizeof(ElfW(Rela))) return false;
    if (pltrel == DT_RELA && jmprel && pltrelsz) {
        if (hook_rela_table(m, jmprel, pltrelsz / sizeof(ElfW(Rela)), symtab, strtab, strsz,
                            wanted, replacement, original)) return true;
    }
    if (rela && relasz) {
        if (hook_rela_table(m, rela, relasz / sizeof(ElfW(Rela)), symtab, strtab, strsz,
                            wanted, replacement, original)) return true;
    }
    return false;
}

// --------------------------- tiny GLES2 batch renderer ----------------------
struct Vertex { float x, y, r, g, b, a; };
constexpr size_t kMaxVertices = 24000;
Vertex g_vertices[kMaxVertices];
size_t g_vertex_count = 0;
GLuint g_program = 0, g_vbo = 0;
GLint g_a_pos = -1, g_a_color = -1, g_u_screen = -1;

void add_quad(float x0, float y0, float x1, float y1, float r, float g, float b, float a) {
    if (g_vertex_count + 6 > kMaxVertices) return;
    Vertex v[6] = {
        {x0,y0,r,g,b,a},{x1,y0,r,g,b,a},{x1,y1,r,g,b,a},
        {x0,y0,r,g,b,a},{x1,y1,r,g,b,a},{x0,y1,r,g,b,a},
    };
    memcpy(g_vertices + g_vertex_count, v, sizeof(v));
    g_vertex_count += 6;
}

void glyph_rows(char c, uint8_t out[7]) {
    memset(out, 0, 7);
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
#define G(a,b,c_,d,e,f,g_) do{out[0]=a;out[1]=b;out[2]=c_;out[3]=d;out[4]=e;out[5]=f;out[6]=g_;}while(0)
    switch (c) {
        case 'A': G(14,17,17,31,17,17,17); break; case 'B': G(30,17,17,30,17,17,30); break;
        case 'C': G(15,16,16,16,16,16,15); break; case 'D': G(30,17,17,17,17,17,30); break;
        case 'E': G(31,16,16,30,16,16,31); break; case 'F': G(31,16,16,30,16,16,16); break;
        case 'G': G(15,16,16,23,17,17,14); break; case 'H': G(17,17,17,31,17,17,17); break;
        case 'I': G(31,4,4,4,4,4,31); break; case 'J': G(7,2,2,2,18,18,12); break;
        case 'K': G(17,18,20,24,20,18,17); break; case 'L': G(16,16,16,16,16,16,31); break;
        case 'M': G(17,27,21,21,17,17,17); break; case 'N': G(17,25,21,19,17,17,17); break;
        case 'O': G(14,17,17,17,17,17,14); break; case 'P': G(30,17,17,30,16,16,16); break;
        case 'Q': G(14,17,17,17,21,18,13); break; case 'R': G(30,17,17,30,20,18,17); break;
        case 'S': G(15,16,16,14,1,1,30); break; case 'T': G(31,4,4,4,4,4,4); break;
        case 'U': G(17,17,17,17,17,17,14); break; case 'V': G(17,17,17,17,17,10,4); break;
        case 'W': G(17,17,17,21,21,21,10); break; case 'X': G(17,17,10,4,10,17,17); break;
        case 'Y': G(17,17,10,4,4,4,4); break; case 'Z': G(31,1,2,4,8,16,31); break;
        case '0': G(14,17,19,21,25,17,14); break; case '1': G(4,12,4,4,4,4,14); break;
        case '2': G(14,17,1,2,4,8,31); break; case '3': G(30,1,1,14,1,1,30); break;
        case '4': G(2,6,10,18,31,2,2); break; case '5': G(31,16,16,30,1,1,30); break;
        case '6': G(14,16,16,30,17,17,14); break; case '7': G(31,1,2,4,8,8,8); break;
        case '8': G(14,17,17,14,17,17,14); break; case '9': G(14,17,17,15,1,1,14); break;
        case '-': G(0,0,0,31,0,0,0); break; case '_': G(0,0,0,0,0,0,31); break;
        case '.': G(0,0,0,0,0,12,12); break; case ':': G(0,12,12,0,12,12,0); break;
        case '/': G(1,1,2,4,8,16,16); break; case '+': G(0,4,4,31,4,4,0); break;
        case '<': G(1,2,4,8,4,2,1); break; case '>': G(16,8,4,2,4,8,16); break;
        default: break;
    }
#undef G
}

void add_text(float x, float y, const char *text, float scale, float r, float g, float b, float a,
              size_t max_chars = 32) {
    if (!text) return;
    float cx = x;
    for (size_t n = 0; text[n] && n < max_chars; ++n) {
        char c = text[n];
        if (c == ' ') { cx += 6 * scale; continue; }
        uint8_t rows[7]; glyph_rows(c, rows);
        for (int row = 0; row < 7; ++row) for (int col = 0; col < 5; ++col) {
            if (rows[row] & (1u << (4 - col))) {
                add_quad(cx + col * scale, y + row * scale,
                         cx + (col + 0.85f) * scale, y + (row + 0.85f) * scale, r,g,b,a);
            }
        }
        cx += 6 * scale;
    }
}


bool is_probe_kind(const ConfigEntry &e) {
    return g_cfg && g_cfg->version >= 4 && (e.flags & F_PROBE_READ_ONLY) != 0 &&
           (e.kind == K_PROBE_BOOL || e.kind == K_PROBE_INT || e.kind == K_PROBE_UINT || e.kind == K_PROBE_FLOAT);
}

const char *probe_field_label(const ConfigEntry &e) {
    const char *sep = static_cast<const char *>(memchr(e.label, 0x1f, sizeof(e.label)));
    return sep && sep + 1 < e.label + sizeof(e.label) && sep[1] ? sep + 1 : e.label;
}

bool probe_owner(const ConfigEntry &e, std::string *out) {
    if (!out) return false;
    const char *sep = static_cast<const char *>(memchr(e.label, 0x1f, sizeof(e.label)));
    if (!sep || sep == e.label) return false;
    out->assign(e.label, static_cast<size_t>(sep - e.label));
    return !out->empty();
}

struct ProbeIl2CppApi {
    void *handle = nullptr;
    void *(*domain_get)() = nullptr;
    const void **(*domain_get_assemblies)(const void *, size_t *) = nullptr;
    const void *(*assembly_get_image)(const void *) = nullptr;
    void *(*class_from_name)(const void *, const char *, const char *) = nullptr;
    bool ready = false;
};
ProbeIl2CppApi g_probe_api{};

bool resolve_probe_il2cpp_api() {
    if (g_probe_api.ready) return true;
    void *h = dlopen(g_cfg ? g_cfg->target_so : "libil2cpp.so", RTLD_NOW | RTLD_NOLOAD);
    if (!h && g_target.name[0]) h = dlopen(g_target.name, RTLD_NOW | RTLD_NOLOAD);
    if (!h) return false;
    g_probe_api.handle = h;
    g_probe_api.domain_get = reinterpret_cast<void *(*)()>(dlsym(h, "il2cpp_domain_get"));
    g_probe_api.domain_get_assemblies = reinterpret_cast<const void **(*)(const void *, size_t *)>(dlsym(h, "il2cpp_domain_get_assemblies"));
    g_probe_api.assembly_get_image = reinterpret_cast<const void *(*)(const void *)>(dlsym(h, "il2cpp_assembly_get_image"));
    g_probe_api.class_from_name = reinterpret_cast<void *(*)(const void *, const char *, const char *)>(dlsym(h, "il2cpp_class_from_name"));
    g_probe_api.ready = g_probe_api.domain_get && g_probe_api.domain_get_assemblies &&
                        g_probe_api.assembly_get_image && g_probe_api.class_from_name;
    MKLOGI("probe il2cpp api: %s", g_probe_api.ready ? "ready" : "unavailable");
    return g_probe_api.ready;
}

void *resolve_probe_class(const ConfigEntry &e) {
    if (!resolve_probe_il2cpp_api()) return nullptr;
    std::string owner;
    if (!probe_owner(e, &owner)) return nullptr;
    std::string ns, name = owner;
    size_t dot = owner.rfind('.');
    if (dot != std::string::npos) { ns = owner.substr(0, dot); name = owner.substr(dot + 1); }
    void *domain = g_probe_api.domain_get();
    if (!domain || name.empty()) return nullptr;
    size_t count = 0;
    const void **assemblies = g_probe_api.domain_get_assemblies(domain, &count);
    if (!assemblies || !count || count > 4096) return nullptr;
    for (size_t i = 0; i < count; ++i) {
        const void *image = g_probe_api.assembly_get_image(assemblies[i]);
        if (!image) continue;
        void *klass = g_probe_api.class_from_name(image, ns.c_str(), name.c_str());
        if (klass) return klass;
    }
    return nullptr;
}

bool safe_read(uintptr_t address, void *dst, size_t size) {
    if (!address || !dst || !size) return false;
    iovec local{dst, size};
    iovec remote{reinterpret_cast<void *>(address), size};
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == static_cast<ssize_t>(size);
}

bool read_probe_value(const ConfigEntry &e, uintptr_t object, double *out) {
    if (!out || !object || e.rva > 0x100000) return false;
    uintptr_t address = object + static_cast<uintptr_t>(e.rva);
    switch (e.kind) {
        case K_PROBE_BOOL: {
            uint8_t v = 0; if (!safe_read(address, &v, sizeof(v)) || v > 1) return false; *out = v ? 1.0 : 0.0; return true;
        }
        case K_PROBE_INT: {
            int32_t v = 0; if (!safe_read(address, &v, sizeof(v))) return false; *out = static_cast<double>(v); return true;
        }
        case K_PROBE_UINT: {
            uint32_t v = 0; if (!safe_read(address, &v, sizeof(v))) return false; *out = static_cast<double>(v); return true;
        }
        case K_PROBE_FLOAT: {
            float v = 0.0f; if (!safe_read(address, &v, sizeof(v)) || !std::isfinite(v) || std::fabs(v) > 1.0e9f) return false; *out = static_cast<double>(v); return true;
        }
        default: return false;
    }
}

bool object_has_class(uintptr_t object, void *klass) {
    uintptr_t head = 0;
    return object && klass && safe_read(object, &head, sizeof(head)) && head == reinterpret_cast<uintptr_t>(klass);
}

bool scan_heap_for_class(void *klass, const ConfigEntry &e, uintptr_t *object_out, double *value_out) {
    if (!klass || !object_out || !value_out) return false;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return false;
    constexpr size_t kChunk = 256 * 1024;
    std::vector<uint8_t> buf(kChunk + sizeof(uintptr_t));
    char line[512];
    const uintptr_t needle = reinterpret_cast<uintptr_t>(klass);
    size_t scanned = 0;
    constexpr size_t kMaxScanBytes = 768u * 1024u * 1024u;
    bool found = false;
    while (!found && fgets(line, sizeof(line), maps)) {
        unsigned long lo = 0, hi = 0; char perms[5]{}; char path[256]{};
        int fields = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\\n]", &lo, &hi, perms, path);
        if (fields < 3 || perms[0] != 'r' || perms[1] != 'w' || perms[3] != 'p' || hi <= lo) continue;
        if (fields >= 4 && (strstr(path, ".so") || strstr(path, "[stack") || strstr(path, "/dev/") || strstr(path, "/system/") || strstr(path, "/apex/"))) continue;
        uintptr_t pos = (static_cast<uintptr_t>(lo) + sizeof(uintptr_t) - 1u) & ~(static_cast<uintptr_t>(sizeof(uintptr_t)) - 1u);
        const uintptr_t end = static_cast<uintptr_t>(hi);
        while (!found && pos + sizeof(uintptr_t) <= end && scanned < kMaxScanBytes) {
            size_t n = static_cast<size_t>(end - pos); if (n > kChunk) n = kChunk;
            iovec local{buf.data(), n}; iovec remote{reinterpret_cast<void *>(pos), n};
            ssize_t got = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
            if (got > 0) {
                scanned += static_cast<size_t>(got);
                size_t usable = static_cast<size_t>(got);
                for (size_t off = 0; off + sizeof(uintptr_t) <= usable; off += sizeof(uintptr_t)) {
                    uintptr_t word = 0; memcpy(&word, buf.data() + off, sizeof(word));
                    if (word != needle) continue;
                    uintptr_t obj = pos + off; double value = 0.0;
                    if (read_probe_value(e, obj, &value)) { *object_out = obj; *value_out = value; found = true; break; }
                }
            }
            pos += n;
        }
        if (scanned >= kMaxScanBytes) break;
    }
    fclose(maps);
    return found;
}

bool refresh_probe(uint32_t i, bool allow_scan) {
    if (!g_cfg || i >= g_cfg->count || !is_probe_kind(g_entries[i])) return false;
    const ConfigEntry &e = g_entries[i]; ProbeState &p = g_probe[i];
    if (!p.klass) p.klass = resolve_probe_class(e);
    if (!p.klass) { MKLOGW("probe %s class resolution failed", e.id); return false; }
    double value = 0.0;
    if (p.object && object_has_class(p.object, p.klass) && read_probe_value(e, p.object, &value)) {
        if (p.found && std::fabs(value - p.value) > (e.kind == K_PROBE_FLOAT ? 0.0001 : 0.0)) { p.previous = p.value; ++p.changes; }
        p.value = value; p.found = true; p.last_sample_ms = 0; return true;
    }
    p.object = 0; p.found = false;
    if (!allow_scan) return false;
    uintptr_t object = 0;
    if (!scan_heap_for_class(p.klass, e, &object, &value)) { MKLOGI("probe %s: no live object found", e.id); return false; }
    p.object = object; p.value = value; p.previous = value; p.changes = 0; p.found = true;
    MKLOGI("probe %s: object=%p field=+0x%llx value=%g", e.id, reinterpret_cast<void *>(object),
           static_cast<unsigned long long>(e.rva), value);
    return true;
}

void sample_probes() {
    if (!g_cfg || g_cfg->version < 4) return;
    static uint64_t last = 0; uint64_t now = static_cast<uint64_t>(clock());
    // draw_overlay runs per frame; keep reads bounded without any background writer.
    if (last && now - last < CLOCKS_PER_SEC / 4) return; last = now;
    for (uint32_t i = 0; i < g_cfg->count; ++i) if (is_probe_kind(g_entries[i]) && g_probe[i].object) refresh_probe(i, false);
}

GLuint compile_shader(GLenum type, const char *src) {
    GLuint s = glCreateShader(type); glShaderSource(s, 1, &src, nullptr); glCompileShader(s);
    GLint ok = 0; glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
    if (!ok) { char log[256]{}; glGetShaderInfoLog(s, sizeof(log), nullptr, log); MKLOGE("shader: %s", log); glDeleteShader(s); return 0; }
    return s;
}

bool ensure_gl() {
    if (g_program) return true;
    static const char *vs =
        "attribute vec2 aPos; attribute vec4 aColor; uniform vec2 uScreen; varying vec4 vColor;"
        "void main(){vec2 p=(aPos/uScreen)*2.0-1.0;gl_Position=vec4(p.x,-p.y,0.0,1.0);vColor=aColor;}";
    static const char *fs =
        "precision mediump float; varying vec4 vColor; void main(){gl_FragColor=vColor;}";
    GLuint v = compile_shader(GL_VERTEX_SHADER, vs), f = compile_shader(GL_FRAGMENT_SHADER, fs);
    if (!v || !f) return false;
    g_program = glCreateProgram(); glAttachShader(g_program, v); glAttachShader(g_program, f); glLinkProgram(g_program);
    glDeleteShader(v); glDeleteShader(f);
    GLint ok = 0; glGetProgramiv(g_program, GL_LINK_STATUS, &ok);
    if (!ok) { MKLOGE("overlay program link failed"); glDeleteProgram(g_program); g_program = 0; return false; }
    g_a_pos = glGetAttribLocation(g_program, "aPos");
    g_a_color = glGetAttribLocation(g_program, "aColor");
    g_u_screen = glGetUniformLocation(g_program, "uScreen");
    glGenBuffers(1, &g_vbo);
    return g_vbo != 0;
}

void apply_control(uint32_t i) {
    if (!g_ready.load() || !g_cfg || i >= g_cfg->count) return;
    const ConfigEntry &e = g_entries[i];
    if (is_probe_kind(e)) { refresh_probe(i, true); return; }
    uintptr_t fn = 0;
    if (!executable_rva(g_target, e.rva, &fn)) {
        MKLOGE("control %s RVA 0x%llx is not executable", e.id,
               static_cast<unsigned long long>(e.rva));
        return;
    }

    const bool il2cpp = (e.flags & F_ABI_IL2CPP) != 0;
    const bool instance_call = (e.flags & F_INSTANCE) != 0;
    void *instance = nullptr;
    if (instance_call) {
        if (!il2cpp || !e.resolver_rva) {
            MKLOGE("control %s has invalid instance resolver config", e.id);
            return;
        }
        uintptr_t resolver = 0;
        if (!executable_rva(g_target, e.resolver_rva, &resolver)) {
            MKLOGE("control %s resolver RVA 0x%llx is not executable", e.id,
                   static_cast<unsigned long long>(e.resolver_rva));
            return;
        }
        if ((e.flags & F_RESOLVER_RETURN_PTR) != 0) {
            using Resolver = void *(*)(const void *);
            instance = reinterpret_cast<Resolver>(resolver)(nullptr);
            if (!instance) {
                MKLOGW("control %s return_ptr resolver returned no object", e.id);
                return;
            }
        } else {
            using Resolver = bool (*)(void **, const void *);
            if (!reinterpret_cast<Resolver>(resolver)(&instance, nullptr) || !instance) {
                MKLOGW("control %s out_ptr_bool resolver returned no object", e.id);
                return;
            }
        }
    }

    MKLOGI("apply %s kind=%u rva=0x%llx resolver=0x%llx abi=%s instance=%d value=%g",
           e.id, e.kind, static_cast<unsigned long long>(e.rva),
           static_cast<unsigned long long>(e.resolver_rva), il2cpp ? "il2cpp" : "native",
           instance_call ? 1 : 0, g_state[i].value);

    if (instance_call) {
        switch (e.kind) {
            case K_ACTION: reinterpret_cast<void (*)(void *, const void *)>(fn)(instance, nullptr); break;
            case K_BOOL: reinterpret_cast<void (*)(void *, bool, const void *)>(fn)(instance, g_state[i].value != 0.0f, nullptr); break;
            case K_INT: reinterpret_cast<void (*)(void *, int32_t, const void *)>(fn)(instance, static_cast<int32_t>(lroundf(g_state[i].value)), nullptr); break;
            case K_FLOAT: reinterpret_cast<void (*)(void *, float, const void *)>(fn)(instance, g_state[i].value, nullptr); break;
            default: break;
        }
        return;
    }

    if (il2cpp) {
        switch (e.kind) {
            case K_ACTION: reinterpret_cast<void (*)(const void *)>(fn)(nullptr); break;
            case K_BOOL: reinterpret_cast<void (*)(bool, const void *)>(fn)(g_state[i].value != 0.0f, nullptr); break;
            case K_INT: reinterpret_cast<void (*)(int32_t, const void *)>(fn)(static_cast<int32_t>(lroundf(g_state[i].value)), nullptr); break;
            case K_FLOAT: reinterpret_cast<void (*)(float, const void *)>(fn)(g_state[i].value, nullptr); break;
            default: break;
        }
    } else {
        switch (e.kind) {
            case K_ACTION: reinterpret_cast<void (*)()>(fn)(); break;
            case K_BOOL: reinterpret_cast<void (*)(bool)>(fn)(g_state[i].value != 0.0f); break;
            case K_INT: reinterpret_cast<void (*)(int32_t)>(fn)(static_cast<int32_t>(lroundf(g_state[i].value))); break;
            case K_FLOAT: reinterpret_cast<void (*)(float)>(fn)(g_state[i].value); break;
            default: break;
        }
    }
}

struct UiGeom {
    float scale = 1.0f;
    float left = 0.0f;
    float top = 0.0f;
    float width = 0.0f;
    float row_h = 0.0f;
    float title_h = 0.0f;
    float tabs_h = 0.0f;
    float header_h = 0.0f;
    int max_visible = 1;
};

uint32_t entry_tab(const ConfigEntry &e) {
    if (!g_cfg || g_cfg->version < 3) return TAB_ALL;
    uint32_t tab = static_cast<uint32_t>(e.reserved[0]);
    return tab < TAB_COUNT ? tab : TAB_ALL;
}

const char *tab_label(int tab) {
    switch (tab) {
        case TAB_COMBAT: return "CMB";
        case TAB_PLAYER: return "PLY";
        case TAB_RESOURCES: return "RES";
        case TAB_WORLD: return "WRL";
        case TAB_DEBUG: return "DBG";
        default: return "ALL";
    }
}

int collect_tab_indices(int tab, int out[kMaxControls]) {
    if (!g_cfg) return 0;
    int count = 0;
    for (uint32_t i = 0; i < g_cfg->count && count < static_cast<int>(kMaxControls); ++i) {
        if (tab == static_cast<int>(TAB_ALL) || entry_tab(g_entries[i]) == static_cast<uint32_t>(tab)) {
            out[count++] = static_cast<int>(i);
        }
    }
    return count;
}

UiGeom ui_geom(int screen_w, int screen_h) {
    UiGeom g{};
    const float sx = screen_w / 1080.0f, sy = screen_h / 1920.0f;
    g.scale = sx < sy ? sx : sy;
    const int default_x = static_cast<int>(24.0f * g.scale);
    const int default_y = static_cast<int>(40.0f * g.scale);
    if (g_menu_x.load() < 0) g_menu_x.store(default_x);
    if (g_menu_y.load() < 0) g_menu_y.store(default_y);
    g.left = static_cast<float>(g_menu_x.load());
    g.top = static_cast<float>(g_menu_y.load());
    const float max_width = 620.0f * g.scale;
    const float room = screen_w - g.left - 16.0f * g.scale;
    g.width = room < max_width ? room : max_width;
    if (g.width < 320.0f * g.scale) g.width = 320.0f * g.scale;
    g.row_h = 58.0f * g.scale;
    g.title_h = 62.0f * g.scale;
    g.tabs_h = 42.0f * g.scale;
    g.header_h = g.title_h + g.tabs_h;
    g.max_visible = static_cast<int>((screen_h - (g.top + g.header_h) - 24.0f * g.scale) / g.row_h);
    if (g.max_visible < 1) g.max_visible = 1;
    return g;
}

void clamp_menu_position(int screen_w, int screen_h, float width, float height, float scale) {
    int x = g_menu_x.load(), y = g_menu_y.load();
    const int margin = static_cast<int>(8.0f * scale);
    int max_x = screen_w - static_cast<int>(width) - margin;
    int max_y = screen_h - static_cast<int>(height) - margin;
    if (max_x < margin) max_x = margin;
    if (max_y < margin) max_y = margin;
    if (x < margin) x = margin; if (x > max_x) x = max_x;
    if (y < margin) y = margin; if (y > max_y) y = max_y;
    g_menu_x.store(x); g_menu_y.store(y);
}

void reset_controls() {
    if (!g_cfg) return;
    for (uint32_t i = 0; i < g_cfg->count; ++i) {
        const ConfigEntry &e = g_entries[i];
        if (e.kind == K_ACTION || is_probe_kind(e)) continue;
        g_state[i].value = e.default_value;
        apply_control(i);
    }
    MKLOGI("menu reset: restored defaults for non-action controls");
}

void handle_tap(int x, int y, int screen_w, int screen_h) {
    if (!g_cfg) return;
    UiGeom g = ui_geom(screen_w, screen_h);
    const float left = g.left, top = g.top, scale = g.scale, width = g.width;
    if (!g_visible.load()) {
        if (x >= left && x <= left + 72 * scale && y >= top && y <= top + 72 * scale) g_visible.store(true);
        return;
    }

    int filtered[kMaxControls]{};
    int selected_tab = g_tab.load();
    if (selected_tab < 0 || selected_tab >= static_cast<int>(TAB_COUNT)) { selected_tab = 0; g_tab.store(0); }
    int filtered_count = collect_tab_indices(selected_tab, filtered);
    int pages = (filtered_count + g.max_visible - 1) / g.max_visible; if (pages < 1) pages = 1;
    int page = g_page.load(); if (page >= pages) { page = 0; g_page.store(0); }

    if (y >= top && y <= top + g.title_h) {
        if (x >= left + width - 42 * scale) { g_visible.store(false); return; }
        if (x >= left + width - 84 * scale) { reset_controls(); return; }
        if (pages > 1 && x >= left + width - 140 * scale && x < left + width - 112 * scale) {
            g_page.store(page > 0 ? page - 1 : pages - 1); return;
        }
        if (pages > 1 && x >= left + width - 112 * scale && x < left + width - 84 * scale) {
            g_page.store((page + 1) % pages); return;
        }
        return;
    }

    if (y >= top + g.title_h && y < top + g.header_h) {
        float tab_w = width / static_cast<float>(TAB_COUNT);
        int tab = static_cast<int>((x - left) / tab_w);
        if (tab >= 0 && tab < static_cast<int>(TAB_COUNT)) {
            g_tab.store(tab); g_page.store(0);
        }
        return;
    }

    float rows_top = top + g.header_h;
    if (y < rows_top) return;
    int local = static_cast<int>((y - rows_top) / g.row_h);
    int filtered_pos = page * g.max_visible + local;
    if (local < 0 || local >= g.max_visible || filtered_pos < 0 || filtered_pos >= filtered_count) return;
    int idx = filtered[filtered_pos];
    const ConfigEntry &e = g_entries[idx];
    if (is_probe_kind(e)) { refresh_probe(static_cast<uint32_t>(idx), true); return; }
    if (e.kind == K_BOOL) {
        g_state[idx].value = g_state[idx].value == 0.0f ? 1.0f : 0.0f;
    } else if (e.kind == K_INT || e.kind == K_FLOAT) {
        float t = (x - (left + width * 0.48f)) / (width * 0.48f);
        if (t < 0) t = 0; if (t > 1) t = 1;
        g_state[idx].value = e.min_value + (e.max_value - e.min_value) * t;
    }
    apply_control(static_cast<uint32_t>(idx));
}

void handle_touch(int action, int x, int y, int screen_w, int screen_h) {
    UiGeom g = ui_geom(screen_w, screen_h);
    const float icon = 72.0f * g.scale;
    if (action == AMOTION_EVENT_ACTION_DOWN) {
        g_drag_moved.store(0);
        g_drag_start_x.store(x); g_drag_start_y.store(y);
        if (!g_visible.load()) {
            if (x >= g.left && x <= g.left + icon && y >= g.top && y <= g.top + icon) {
                g_drag_mode.store(2);
                g_drag_dx.store(x - static_cast<int>(g.left));
                g_drag_dy.store(y - static_cast<int>(g.top));
            }
            return;
        }
        // Only the title body drags the panel. Reset/page/close buttons remain clickable.
        if (y >= g.top && y <= g.top + g.title_h && x < g.left + g.width - 150.0f * g.scale) {
            g_drag_mode.store(1);
            g_drag_dx.store(x - static_cast<int>(g.left));
            g_drag_dy.store(y - static_cast<int>(g.top));
            return;
        }
        if (y >= g.top + g.header_h) {
            int filtered[kMaxControls]{};
            int tab = g_tab.load();
            int count = collect_tab_indices(tab, filtered);
            int pages = (count + g.max_visible - 1) / g.max_visible; if (pages < 1) pages = 1;
            int page = g_page.load(); if (page >= pages) page = 0;
            int local = static_cast<int>((y - (g.top + g.header_h)) / g.row_h);
            int pos = page * g.max_visible + local;
            if (local >= 0 && local < g.max_visible && pos >= 0 && pos < count) g_pressed_index.store(filtered[pos]);
        }
        return;
    }
    if (action == AMOTION_EVENT_ACTION_MOVE) {
        int mode = g_drag_mode.load();
        if (!mode) return;
        int nx = x - g_drag_dx.load();
        int ny = y - g_drag_dy.load();
        int dx = x - g_drag_start_x.load(), dy = y - g_drag_start_y.load();
        if (dx*dx + dy*dy > static_cast<int>(36.0f * g.scale * g.scale)) g_drag_moved.store(1);
        g_menu_x.store(nx); g_menu_y.store(ny);
        float h = mode == 2 ? icon : (g.header_h + g.row_h * 2.0f);
        float w = mode == 2 ? icon : g.width;
        clamp_menu_position(screen_w, screen_h, w, h, g.scale);
        return;
    }
    if (action == AMOTION_EVENT_ACTION_UP) {
        int mode = g_drag_mode.exchange(0);
        bool moved = g_drag_moved.exchange(0) != 0;
        if (mode) {
            g_pressed_index.store(-1);
            if (!moved && mode == 2) g_visible.store(true);
            return;
        }
        handle_tap(x, y, screen_w, screen_h);
        g_pressed_index.store(-1);
    }
}

void draw_overlay() {
    if (!g_ready.load() || !g_cfg || !ensure_gl()) return;
    sample_probes();
    GLint vp[4]{}; glGetIntegerv(GL_VIEWPORT, vp);
    int screen_w = vp[2], screen_h = vp[3];
    if (screen_w <= 0 || screen_h <= 0) return;
    static uint32_t last_touch_seq = 0;
    uint32_t seq = g_touch_seq.load();
    if (seq != last_touch_seq) {
        last_touch_seq = seq;
        handle_touch(g_touch_action.load(), g_touch_x.load(), g_touch_y.load(), screen_w, screen_h);
    }

    g_vertex_count = 0;
    UiGeom g = ui_geom(screen_w, screen_h);
    const float scale = g.scale;
    if (!g_visible.load()) {
        clamp_menu_position(screen_w, screen_h, 72*scale, 72*scale, scale);
        g = ui_geom(screen_w, screen_h);
        add_quad(g.left, g.top, g.left + 72 * scale, g.top + 72 * scale, 0.08f,0.12f,0.20f,0.92f);
        add_text(g.left + 13*scale, g.top + 22*scale, "MK", 4.2f*scale, 0.85f,0.95f,1.0f,1.0f, 2);
    } else {
        int filtered[kMaxControls]{};
        int selected_tab = g_tab.load();
        if (selected_tab < 0 || selected_tab >= static_cast<int>(TAB_COUNT)) { selected_tab = 0; g_tab.store(0); }
        int filtered_count = collect_tab_indices(selected_tab, filtered);
        int pages = (filtered_count + g.max_visible - 1) / g.max_visible; if (pages < 1) pages = 1;
        int page = g_page.load(); if (page >= pages) { page = 0; g_page.store(0); }
        int start = page * g.max_visible;
        int rows = filtered_count - start; if (rows > g.max_visible) rows = g.max_visible; if (rows < 0) rows = 0;
        const float height = g.header_h + rows * g.row_h;
        clamp_menu_position(screen_w, screen_h, g.width, height > g.header_h ? height : g.header_h, scale);
        g = ui_geom(screen_w, screen_h);
        add_quad(g.left, g.top, g.left + g.width, g.top + height, 0.055f,0.075f,0.12f,0.96f);
        add_quad(g.left, g.top, g.left + g.width, g.top + g.title_h, 0.08f,0.13f,0.22f,1.0f);
        add_text(g.left + 18*scale, g.top + 20*scale, g_cfg->title, 2.6f*scale, 0.90f,0.96f,1.0f,1.0f, 22);
        if (pages > 1) {
            add_text(g.left + g.width - 136*scale, g.top + 20*scale, "<", 2.4f*scale, 0.75f,0.85f,1.0f,1.0f, 1);
            add_text(g.left + g.width - 108*scale, g.top + 20*scale, ">", 2.4f*scale, 0.75f,0.85f,1.0f,1.0f, 1);
        }
        add_text(g.left + g.width - 78*scale, g.top + 20*scale, "R", 2.4f*scale, 0.70f,0.95f,0.78f,1.0f, 1);
        add_text(g.left + g.width - 36*scale, g.top + 20*scale, "X", 2.4f*scale, 1.0f,0.55f,0.55f,1.0f, 1);

        float tab_w = g.width / static_cast<float>(TAB_COUNT);
        for (int tab = 0; tab < static_cast<int>(TAB_COUNT); ++tab) {
            float x0 = g.left + tab * tab_w;
            float y0 = g.top + g.title_h;
            bool active = tab == selected_tab;
            add_quad(x0, y0, x0 + tab_w, y0 + g.tabs_h,
                     active ? 0.16f : 0.07f, active ? 0.32f : 0.10f, active ? 0.56f : 0.16f, 1.0f);
            add_text(x0 + 10*scale, y0 + 14*scale, tab_label(tab), 1.7f*scale,
                     active ? 1.0f : 0.72f, active ? 1.0f : 0.78f, active ? 1.0f : 0.88f, 1.0f, 3);
        }

        for (int i = 0; i < rows; ++i) {
            int control_index = filtered[start + i];
            const ConfigEntry &e = g_entries[control_index];
            float y0 = g.top + g.header_h + i * g.row_h;
            if (i & 1) add_quad(g.left, y0, g.left + g.width, y0 + g.row_h, 0.07f,0.09f,0.14f,0.8f);
            if (g_pressed_index.load() == control_index)
                add_quad(g.left, y0, g.left + g.width, y0 + g.row_h, 0.16f,0.24f,0.36f,0.45f);
            const char *display_label = is_probe_kind(e) ? probe_field_label(e) : (e.label[0] ? e.label : e.id);
            add_text(g.left + 16*scale, y0 + 19*scale, display_label,
                     2.0f*scale, 0.88f,0.91f,0.96f,1.0f, 24);
            float bx0 = g.left + g.width * 0.70f, bx1 = g.left + g.width - 14*scale;
            if (is_probe_kind(e)) {
                ProbeState &p = g_probe[control_index]; char value[32]{};
                if (!p.found) snprintf(value, sizeof(value), "SCAN");
                else if (e.kind == K_PROBE_BOOL) snprintf(value, sizeof(value), "%s%s", p.value != 0.0 ? "TRUE" : "FALSE", p.changes ? "*" : "");
                else if (e.kind == K_PROBE_FLOAT) snprintf(value, sizeof(value), "%.3g%s", p.value, p.changes ? "*" : "");
                else snprintf(value, sizeof(value), "%.0f%s", p.value, p.changes ? "*" : "");
                add_quad(bx0, y0 + 12*scale, bx1, y0 + g.row_h - 12*scale,
                         p.found?0.12f:0.30f, p.found?0.42f:0.28f, p.found?0.62f:0.20f, 1.0f);
                add_text(bx0 + 8*scale, y0 + 20*scale, value, 1.6f*scale, 1,1,1,1, 10);
            } else if (e.kind == K_BOOL) {
                bool on = g_state[control_index].value != 0.0f;
                add_quad(bx0, y0 + 12*scale, bx1, y0 + g.row_h - 12*scale,
                         on?0.18f:0.25f, on?0.62f:0.28f, on?0.32f:0.32f, 1.0f);
                add_text(bx0 + 12*scale, y0 + 20*scale, on?"ON":"OFF", 1.8f*scale, 1,1,1,1, 3);
            } else if (e.kind == K_ACTION) {
                add_quad(bx0, y0 + 12*scale, bx1, y0 + g.row_h - 12*scale, 0.16f,0.36f,0.66f,1.0f);
                add_text(bx0 + 12*scale, y0 + 20*scale, "RUN", 1.8f*scale, 1,1,1,1, 3);
            } else {
                float denom = e.max_value - e.min_value;
                float t = denom != 0 ? (g_state[control_index].value - e.min_value) / denom : 0;
                if (t < 0) t = 0; if (t > 1) t = 1;
                float sx0 = g.left + g.width * 0.48f;
                add_quad(sx0, y0 + 23*scale, bx1, y0 + 35*scale, 0.18f,0.22f,0.30f,1.0f);
                add_quad(sx0, y0 + 23*scale, sx0 + (bx1 - sx0) * t, y0 + 35*scale, 0.20f,0.58f,0.92f,1.0f);
            }
        }
    }
    if (!g_vertex_count) return;

    GLint old_program = 0, old_vbo = 0, old_src = 0, old_dst = 0;
    glGetIntegerv(GL_CURRENT_PROGRAM, &old_program);
    glGetIntegerv(GL_ARRAY_BUFFER_BINDING, &old_vbo);
    glGetIntegerv(GL_BLEND_SRC_RGB, &old_src); glGetIntegerv(GL_BLEND_DST_RGB, &old_dst);
    GLboolean blend = glIsEnabled(GL_BLEND), depth = glIsEnabled(GL_DEPTH_TEST), cull = glIsEnabled(GL_CULL_FACE), scissor = glIsEnabled(GL_SCISSOR_TEST);
    glDisable(GL_DEPTH_TEST); glDisable(GL_CULL_FACE); glDisable(GL_SCISSOR_TEST); glEnable(GL_BLEND); glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glUseProgram(g_program); glUniform2f(g_u_screen, static_cast<float>(screen_w), static_cast<float>(screen_h));
    glBindBuffer(GL_ARRAY_BUFFER, g_vbo); glBufferData(GL_ARRAY_BUFFER, g_vertex_count * sizeof(Vertex), g_vertices, GL_STREAM_DRAW);
    glEnableVertexAttribArray(static_cast<GLuint>(g_a_pos));
    glEnableVertexAttribArray(static_cast<GLuint>(g_a_color));
    glVertexAttribPointer(static_cast<GLuint>(g_a_pos), 2, GL_FLOAT, GL_FALSE, sizeof(Vertex), reinterpret_cast<void *>(0));
    glVertexAttribPointer(static_cast<GLuint>(g_a_color), 4, GL_FLOAT, GL_FALSE, sizeof(Vertex), reinterpret_cast<void *>(2 * sizeof(float)));
    glDrawArrays(GL_TRIANGLES, 0, static_cast<GLsizei>(g_vertex_count));
    glDisableVertexAttribArray(static_cast<GLuint>(g_a_pos)); glDisableVertexAttribArray(static_cast<GLuint>(g_a_color));
    glBindBuffer(GL_ARRAY_BUFFER, static_cast<GLuint>(old_vbo)); glUseProgram(static_cast<GLuint>(old_program));
    glBlendFunc(static_cast<GLenum>(old_src), static_cast<GLenum>(old_dst));
    if (!blend) glDisable(GL_BLEND); if (depth) glEnable(GL_DEPTH_TEST); if (cull) glEnable(GL_CULL_FACE); if (scissor) glEnable(GL_SCISSOR_TEST);
}

EGLBoolean hooked_swap(EGLDisplay d, EGLSurface s) {
    draw_overlay();
    return g_orig_swap ? g_orig_swap(d, s) : EGL_FALSE;
}

int32_t hooked_get_action(const AInputEvent *event) {
    int32_t action = g_orig_get_action ? g_orig_get_action(event) : 0;
    int32_t masked = action & AMOTION_EVENT_ACTION_MASK;
    if ((masked == AMOTION_EVENT_ACTION_DOWN || masked == AMOTION_EVENT_ACTION_UP || masked == AMOTION_EVENT_ACTION_MOVE) && g_get_x && g_get_y) {
        float x = g_get_x(event, 0), y = g_get_y(event, 0);
        g_touch_x.store(static_cast<int>(x)); g_touch_y.store(static_cast<int>(y));
        g_touch_action.store(masked);
        g_touch_seq.fetch_add(1, std::memory_order_release);
    }
    return action;
}

bool install_ui_hooks() {
    const char *candidates[4] = {g_cfg->render_host, "libunity.so", "libmain.so", "libgame.so"};
    bool swap = false, touch = false;
    void *android = dlopen("libandroid.so", RTLD_NOW | RTLD_NOLOAD);
    if (!android) android = dlopen("libandroid.so", RTLD_NOW);
    g_get_x = android ? reinterpret_cast<FnGetCoord>(dlsym(android, "AMotionEvent_getX")) : nullptr;
    g_get_y = android ? reinterpret_cast<FnGetCoord>(dlsym(android, "AMotionEvent_getY")) : nullptr;
    for (const char *name : candidates) {
        if (!name || !*name) continue;
        Module m{};
        if (!find_module(name, &m)) continue;
        if (!swap) swap = hook_import(m, "eglSwapBuffers", reinterpret_cast<void *>(&hooked_swap), reinterpret_cast<void **>(&g_orig_swap));
        if (!touch) touch = hook_import(m, "AMotionEvent_getAction", reinterpret_cast<void *>(&hooked_get_action), reinterpret_cast<void **>(&g_orig_get_action));
        if (swap && touch) break;
    }
    MKLOGI("ui hooks: swap=%d touch=%d", swap ? 1 : 0, touch ? 1 : 0);
    return swap;
}

void *runtime_main(void *) {
    if (!valid_config()) {
        MKLOGW(".modkitcfg is not configured; runtime stays dormant");
        return nullptr;
    }
    MKLOGI("config: target=%s render=%s controls=%u title=%s", g_cfg->target_so, g_cfg->render_host, g_cfg->count, g_cfg->title);
    if (!wait_module(g_cfg->target_so, &g_target, 60000)) {
        MKLOGE("target module %s did not appear", g_cfg->target_so);
        return nullptr;
    }
    // Address ranges were verified by ModKit before packing. Runtime performs a
    // second mapped-range check and does not auto-apply any feature.
    bool has_probes = false;
    for (uint32_t i = 0; i < g_cfg->count; ++i) {
        const ConfigEntry &e = g_entries[i];
        if (is_probe_kind(e)) { has_probes = true; continue; }
        if (!executable_rva(g_target, e.rva)) {
            MKLOGE("binding %s rva=0x%llx not executable at runtime", e.id,
                   static_cast<unsigned long long>(e.rva));
            return nullptr;
        }
        if ((e.flags & F_INSTANCE) != 0) {
            if ((e.flags & F_ABI_IL2CPP) == 0 || !e.resolver_rva || !executable_rva(g_target, e.resolver_rva)) {
                MKLOGE("binding %s resolver=0x%llx is invalid/not executable at runtime", e.id,
                       static_cast<unsigned long long>(e.resolver_rva));
                return nullptr;
            }
        }
    }
    if (has_probes) resolve_probe_il2cpp_api();
    g_ready.store(true);
    install_ui_hooks();
    MKLOGI("runtime ready; no feature is applied until a menu control is used");
    return nullptr;
}

}  // namespace

extern "C" __attribute__((constructor)) void modkit_runtime_constructor() {
    pthread_t t{};
    if (pthread_create(&t, nullptr, runtime_main, nullptr) == 0) pthread_detach(t);
}
