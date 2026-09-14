#pragma once
// Minimal JNI surface for host-side type checking of jni_main.cpp.
#include <cstdint>
#include <cstdint>
typedef int32_t jint;
typedef uint8_t jboolean;
typedef float jfloat;
typedef double jdouble;
typedef int64_t jlong;
typedef int16_t jshort;
typedef uint16_t jchar;
typedef int8_t jbyte;
typedef uint8_t jsize;
typedef void *jobject;
typedef jobject jclass;
typedef jobject jstring;
#define JNI_TRUE 1
#define JNI_FALSE 0
#define JNI_VERSION_1_6 0x00010006
#define JNIEXPORT
#define JNICALL
struct _JNIEnv;
typedef _JNIEnv JNIEnv;
struct _JavaVM;
typedef _JavaVM JavaVM;
struct _JNIEnv {
    const char *GetStringUTFChars(jstring, jboolean *);
    void ReleaseStringUTFChars(jstring, const char *);
    jstring NewStringUTF(const char *);
    jint GetVersion() { return JNI_VERSION_1_6; }
};
