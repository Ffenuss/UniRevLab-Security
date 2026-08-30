#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/test-corpus/native/multiabi/abi_fixture.c"
OUT="$ROOT/test-corpus/native/multiabi"
CLANG="${CLANG:-clang}"
COMMON=(-fuse-ld=lld -nostdlib -shared -fPIC -Wl,-soname,libunirevlab_abi_fixture.so)
"$CLANG" --target=aarch64-linux-android21 "${COMMON[@]}" "$SRC" -o "$OUT/libfixture-arm64-v8a.so"
"$CLANG" --target=armv7a-linux-androideabi21 "${COMMON[@]}" "$SRC" -o "$OUT/libfixture-armeabi-v7a.so"
"$CLANG" --target=x86_64-linux-android21 "${COMMON[@]}" "$SRC" -o "$OUT/libfixture-x86_64.so"
sha256sum "$OUT"/libfixture-*.so > "$OUT/SHA256SUMS"
