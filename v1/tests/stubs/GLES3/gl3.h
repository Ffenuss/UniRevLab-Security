#pragma once
typedef int GLint;
typedef unsigned int GLuint;
#define GL_VIEWPORT 0x0BA2
static inline void glGetIntegerv(unsigned int pname, GLint *params) { (void)pname; (void)params; }
