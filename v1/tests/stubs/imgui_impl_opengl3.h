#pragma once
// Stub of the OpenGL3 backend header, same entry points as the real one.
#include "imgui.h"
inline bool ImGui_ImplOpenGL3_Init(const char *glsl_version = nullptr);
inline bool ImGui_ImplOpenGL3_Init(const char *) { return true; }
inline void ImGui_ImplOpenGL3_Shutdown() {}
inline void ImGui_ImplOpenGL3_NewFrame() {}
inline void ImGui_ImplOpenGL3_RenderDrawData(ImDrawData *) {}
