cmake_minimum_required(VERSION 3.22)
project(modkit_mobile_native C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(modkit_runtime SHARED modkit_runtime.cpp)
set_target_properties(modkit_runtime PROPERTIES OUTPUT_NAME "mk")
target_compile_options(modkit_runtime PRIVATE -Os -fvisibility=hidden -ffunction-sections -fdata-sections -Wall -Wextra -Wno-unused-parameter)
target_link_options(modkit_runtime PRIVATE -Wl,--gc-sections -Wl,-z,max-page-size=16384 -Wl,--build-id=sha1)
target_link_libraries(modkit_runtime PRIVATE log android EGL GLESv2 dl m)

# Static-analysis disassembly is intentionally isolated from libmk.so, whose
# constructor belongs to the optional runtime/menu payload. Capstone is pinned
# to an immutable upstream commit corresponding to stable release 5.0.9.
include(FetchContent)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_X86_ATT_DISABLE ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_DIET OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG 022575848782a4801fd150fdbc927effcbca0864
    GIT_SHALLOW FALSE
    GIT_PROGRESS FALSE
)
FetchContent_MakeAvailable(capstone)

add_library(modkit_disasm SHARED modkit_disasm.cpp)
set_target_properties(modkit_disasm PROPERTIES OUTPUT_NAME "mkdisasm")
target_compile_options(modkit_disasm PRIVATE -Os -fvisibility=hidden -ffunction-sections -fdata-sections -Wall -Wextra -Wno-unused-parameter)
target_link_options(modkit_disasm PRIVATE -Wl,--gc-sections -Wl,-z,max-page-size=16384 -Wl,--build-id=sha1)
target_link_libraries(modkit_disasm PRIVATE capstone_static log)
