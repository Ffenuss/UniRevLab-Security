#if MODKIT_OVERLAY
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
