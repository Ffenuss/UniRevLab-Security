#!/usr/bin/env bash
set -euo pipefail
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME is required}"
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-24 \
  -DANDROID_STL=c++_static
cmake --build build --parallel
mkdir -p output
cp build/libBedo.so output/libBedo.so
cp libCore.so output/libCore.so
sha256sum output/libBedo.so output/libCore.so > output/SHA256SUMS.txt
readelf -d output/libBedo.so > output/libBedo-dynamic.txt
