#pragma once
#include <cstddef>
#include <cstdint>
typedef unsigned int GLenum;
typedef unsigned char GLboolean;
typedef unsigned int GLbitfield;
typedef void GLvoid;
typedef std::int8_t GLbyte;
typedef std::int16_t GLshort;
typedef int GLint;
typedef int GLsizei;
typedef std::uint8_t GLubyte;
typedef std::uint16_t GLushort;
typedef unsigned int GLuint;
typedef float GLfloat;
typedef float GLclampf;
typedef std::ptrdiff_t GLsizeiptr;
#define GL_FALSE 0
#define GL_TRUE 1
#define GL_VERTEX_SHADER 0x8B31
#define GL_FRAGMENT_SHADER 0x8B30
#define GL_COMPILE_STATUS 0x8B81
#define GL_LINK_STATUS 0x8B82
#define GL_VIEWPORT 0x0BA2
#define GL_CURRENT_PROGRAM 0x8B8D
#define GL_ARRAY_BUFFER 0x8892
#define GL_ARRAY_BUFFER_BINDING 0x8894
#define GL_BLEND 0x0BE2
#define GL_BLEND_SRC_RGB 0x80C9
#define GL_BLEND_DST_RGB 0x80C8
#define GL_DEPTH_TEST 0x0B71
#define GL_CULL_FACE 0x0B44
#define GL_SCISSOR_TEST 0x0C11
#define GL_SRC_ALPHA 0x0302
#define GL_ONE_MINUS_SRC_ALPHA 0x0303
#define GL_STREAM_DRAW 0x88E0
#define GL_FLOAT 0x1406
#define GL_TRIANGLES 0x0004
extern "C" {
GLuint glCreateShader(GLenum);
void glShaderSource(GLuint, GLsizei, const char *const *, const GLint *);
void glCompileShader(GLuint);
void glGetShaderiv(GLuint, GLenum, GLint *);
void glGetShaderInfoLog(GLuint, GLsizei, GLsizei *, char *);
void glDeleteShader(GLuint);
GLuint glCreateProgram(void);
void glAttachShader(GLuint, GLuint);
void glLinkProgram(GLuint);
void glGetProgramiv(GLuint, GLenum, GLint *);
void glDeleteProgram(GLuint);
GLint glGetAttribLocation(GLuint, const char *);
GLint glGetUniformLocation(GLuint, const char *);
void glGenBuffers(GLsizei, GLuint *);
void glGetIntegerv(GLenum, GLint *);
GLboolean glIsEnabled(GLenum);
void glDisable(GLenum);
void glEnable(GLenum);
void glBlendFunc(GLenum, GLenum);
void glUseProgram(GLuint);
void glUniform2f(GLint, GLfloat, GLfloat);
void glBindBuffer(GLenum, GLuint);
void glBufferData(GLenum, GLsizeiptr, const void *, GLenum);
void glEnableVertexAttribArray(GLuint);
void glDisableVertexAttribArray(GLuint);
void glVertexAttribPointer(GLuint, GLint, GLenum, GLboolean, GLsizei, const void *);
void glDrawArrays(GLenum, GLint, GLsizei);
}
