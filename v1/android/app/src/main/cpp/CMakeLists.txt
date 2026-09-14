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
