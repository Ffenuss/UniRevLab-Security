#!/usr/bin/env bash
# Standalone NDK build, no Gradle. Needs $ANDROID_NDK or any ndk/* under $ANDROID_HOME.
set -euo pipefail

ABI="${ABI:-arm64-v8a}"
API="${API:-26}"
NDK="${ANDROID_NDK:-$(ls -d "${ANDROID_HOME:-$HOME/Android/Sdk}"/ndk/* 2>/dev/null | sort -V | tail -1)}"
[ -d "$NDK" ] || { echo "NDK not found: set ANDROID_NDK" >&2; exit 1; }

case "$(uname -s)" in
  Linux)  HOST=linux-x86_64 ;;
  Darwin) HOST=darwin-x86_64 ;;
  *)      HOST=windows-x86_64 ;;
esac

SRC="$(cd "$(dirname "$0")" && pwd)"
OUT="$SRC/build/$ABI"

cmake -S "$SRC/app/src/main/cpp" -B "$OUT" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM="android-$API" \
  -DANDROID_STL=c++_static \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DMODKIT_OVERLAY="${MODKIT_OVERLAY:-ON}" \
  -DMODKIT_HAS_IMGUI="${MODKIT_HAS_IMGUI:-OFF}" \
  -DMODKIT_HAVE_DOBBY="${MODKIT_HAVE_DOBBY:-OFF}" \
  "${EXTRA_CMAKE:-}"

cmake --build "$OUT" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"

echo "libneondrift.so -> $OUT/libneondrift.so"
echo "push into the game's data dir, or:  adb install -r app.apk"
