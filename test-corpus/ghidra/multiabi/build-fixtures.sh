#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$ROOT/test-corpus/ghidra/multiabi/il2cpp_codegen_fixture.c"
OUT="$ROOT/test-corpus/ghidra/multiabi"
CLANG="${CLANG:-clang}"
COMMON=(-fuse-ld=lld -nostdlib -shared -fPIC -Wl,-soname,libunirevlab_il2cpp_fixture.so)
"$CLANG" --target=aarch64-linux-android21 "${COMMON[@]}" "$SRC" -o "$OUT/libil2cpp-fixture-arm64-v8a.so"
"$CLANG" --target=armv7a-linux-androideabi21 "${COMMON[@]}" "$SRC" -o "$OUT/libil2cpp-fixture-armeabi-v7a.so"
"$CLANG" --target=x86_64-linux-android21 "${COMMON[@]}" "$SRC" -o "$OUT/libil2cpp-fixture-x86_64.so"
(cd "$OUT" && sha256sum libil2cpp-fixture-*.so > SHA256SUMS)
