cmake_minimum_required(VERSION 3.22)
project(neondrift CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(MODKIT_OVERLAY "draw the in-GL menu via the eglSwapBuffers hook" ON)
option(MODKIT_HAS_IMGUI "third_party/imgui is vendored" OFF)
option(MODKIT_HAVE_DOBBY "link third_party/dobby instead of the built-in inline hooker" OFF)

add_library(neondrift SHARED
    jni_main.cpp
    modkit.cpp
    game.cpp)

target_include_directories(neondrift PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(neondrift PRIVATE
    MODKIT_TARGET_SO="libil2cpp.so"
    MODKIT_TAG="neondrift"
    MODKIT_OVERLAY=$<BOOL:${MODKIT_OVERLAY}>
    MODKIT_HAS_IMGUI=$<BOOL:${MODKIT_HAS_IMGUI}>
    MODKIT_HAVE_DOBBY=$<BOOL:${MODKIT_HAVE_DOBBY}>)

if(MODKIT_OVERLAY)
    target_sources(neondrift PRIVATE overlay.cpp)
endif()

if(MODKIT_HAS_IMGUI)
    file(GLOB IMGUI_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/imgui/*.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/imgui/backends/imgui_impl_opengl3.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/imgui/backends/imgui_impl_opengl3_loader.h)
    target_sources(neondrift PRIVATE ${IMGUI_SRC})
    target_include_directories(neondrift PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/imgui)
endif()

string(APPEND CMAKE_CXX_FLAGS " -D_GNU_SOURCE -Os -fvisibility=hidden -fno-rtti -Wall -Wno-unused-parameter"
       " -ffunction-sections -fdata-sections -fno-strict-aliasing")
string(APPEND CMAKE_SHARED_LINKER_FLAGS
       " -Wl,--gc-sections -Wl,--exclude-libs,ALL -Wl,-z,max-page-size=16384 -Wl,--build-id=sha1")

target_link_libraries(neondrift PRIVATE log android EGL GLESv3)

if(MODKIT_HAVE_DOBBY AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/dobby/CMakeLists.txt)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../third_party/dobby ${CMAKE_BINARY_DIR}/dobby)
    target_link_libraries(neondrift PRIVATE dobby)
endif()
