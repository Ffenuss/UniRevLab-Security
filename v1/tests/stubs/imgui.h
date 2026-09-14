#pragma once
// ---------------------------------------------------------------------------
//  Hand-written stand-in for Dear ImGui, only used so `pytest` can type-check the
//  generated UI code with a host compiler. It mirrors the real signatures of the
//  subset the generated menu touches; it is not a reimplementation.
// ---------------------------------------------------------------------------
#include <cstdarg>

typedef unsigned int ImGuiWindowFlags;
typedef unsigned int ImGuiInputTextFlags;
typedef unsigned int ImGuiCond;
typedef unsigned int ImGuiTabBarFlags;
typedef int ImGuiID;
typedef unsigned int ImGuiTabItemFlags;

enum ImGuiWindowFlags_ {
    ImGuiWindowFlags_None = 0,
    ImGuiWindowFlags_NoTitleBar = 1 << 0,
    ImGuiWindowFlags_NoResize = 1 << 1,
    ImGuiWindowFlags_NoMove = 1 << 2,
    ImGuiWindowFlags_NoCollapse = 1 << 5,
    ImGuiWindowFlags_AlwaysAutoResize = 1 << 6,
    ImGuiWindowFlags_MenuBar = 1 << 10,
    ImGuiWindowFlags_NoSavedSettings = 1 << 13,
};
enum ImGuiCond_ { ImGuiCond_FirstUseEver = 1 << 2, ImGuiCond_Always = 1 << 1 };
enum ImGuiTabBarFlags_ {
    ImGuiTabBarFlags_None = 0,
    ImGuiTabBarFlags_FittingPolicyScroll = 1 << 5,
};

struct ImVec2 {
    float x = 0, y = 0;
    ImVec2() = default;
    ImVec2(float _x, float _y) : x(_x), y(_y) {}
};
struct ImVec4 {
    float x = 0, y = 0, z = 0, w = 0;
    ImVec4() = default;
    ImVec4(float _x, float _y, float _z, float _w) : x(_x), y(_y), z(_z), w(_w) {}
};

struct ImGuiIO {
    const char *IniFilename = nullptr;
    float FontGlobalScale = 1.0f;
    ImVec2 DisplaySize;
    float DeltaTime = 1.0f / 60.0f;
    ImVec2 MousePos;
    bool MouseDown[5] = {false};
    void AddMouseButtonDown() { MouseDown[0] = true; }
    void AddMouseButtonUp() { MouseDown[0] = false; }
};

struct ImGuiStyle {
    float WindowRounding = 0.0f;
    float GrabMinSize = 0.0f;
    ImVec2 FramePadding;
    ImVec2 WindowPadding;
};

struct ImDrawData;

namespace ImGui {

inline ImGuiIO &GetIO() {
    static ImGuiIO io;
    return io;
}
inline ImGuiStyle &GetStyle() {
    static ImGuiStyle st;
    return st;
}
inline void CreateContext() {}
inline void DestroyContext() {}
inline void StyleColorsDark() {}
inline bool Begin(const char *, bool * = nullptr, ImGuiWindowFlags = 0) { return true; }
inline void End() {}
inline void Separator() {}
inline void SameLine() {}
inline void TextUnformatted(const char *, const char * = nullptr) {}
inline void Text(const char *, ...) {}
inline void TextColored(const ImVec4 &, const char *, ...) {}
inline void TextDisabled(const char *, ...) {}
inline bool Button(const char *, const ImVec2 & = ImVec2()) { return false; }
inline bool SmallButton(const char *) { return false; }
inline bool Checkbox(const char *, bool *) { return false; }
inline bool SliderFloat(const char *, float *, float, float, const char * = nullptr) { return false; }
inline bool DragFloat(const char *, float *, float = 1.0f, float = 0.0f, float = 0.0f,
                      const char * = nullptr) { return false; }
inline void PushID(int) {}
inline void PopID() {}
inline void SetNextItemWidth(float) {}
inline void SetNextWindowPos(const ImVec2 &, ImGuiCond = 0) {}
inline void SetNextWindowSize(const ImVec2 &, ImGuiCond = 0) {}
inline bool BeginTabBar(const char *, ImGuiTabBarFlags = 0) { return true; }
inline void EndTabBar() {}
inline bool BeginTabItem(const char *, bool * = nullptr, ImGuiTabItemFlags = 0) { return true; }
inline void EndTabItem() {}
inline void Render() {}
inline ImDrawData *GetDrawData() { return nullptr; }

}  // namespace ImGui
