#pragma once
// Minimal stand-in for <android/log.h>: lets the generated code be type-checked on a
// desktop compiler in CI, where the NDK headers are not installed.
#include <cstdarg>
enum android_LogPriority {
    ANDROID_LOG_UNKNOWN = 0, ANDROID_LOG_DEFAULT, ANDROID_LOG_VERBOSE, ANDROID_LOG_DEBUG,
    ANDROID_LOG_INFO, ANDROID_LOG_WARN, ANDROID_LOG_ERROR, ANDROID_LOG_FATAL, ANDROID_LOG_SILENT
};
static inline int __android_log_print(int prio, const char *, const char *, ...) {
    (void)prio;
    return 0;
}
