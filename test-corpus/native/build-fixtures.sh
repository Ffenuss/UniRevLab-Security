#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/test-corpus/native/jni_fixture.c"
OUT="$ROOT/app/src/test/resources/fixtures"
mkdir -p "$OUT"
gcc -shared -fPIC -fstack-protector-all -Wl,-z,relro,-z,now -Wl,--build-id -o "$OUT/libjni_hardened.so" "$SRC"
gcc -shared -fPIC -Wl,-z,execstack,-z,norelro -Wl,--build-id -o "$OUT/libjni_weak.so" "$SRC"
