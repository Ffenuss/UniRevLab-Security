#pragma once
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
